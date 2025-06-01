use std::marker::PhantomData;

/// 优化版本：证明知道两个私有输入a和b
/// 计算: a² + b² + a×b×const = out
///
/// 相比原版本的改进：
/// 1. 更紧凑的门设计（一行完成一个操作）
/// 2. 支持加法和乘法
/// 3. 使用Fixed列存储常数
/// 4. 减少了cell的使用量
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};

/// 优化后的电路设计:
/// | a0   | a1   | a2   | const | s_add | s_mul | s_sq |
/// |------|------|------|-------|-------|-------|------|
/// |  a   |      |      |       |   0   |   0   |  1   | <- a²
/// |  b   |      |      |       |   0   |   0   |  1   | <- b²  
/// |  a   |  b   |      | const |   0   |   1   |  0   | <- a×b×const
/// | a²   | b²   | ab×c |       |   1   |   0   |  0   | <- final sum

#[derive(Debug, Clone)]
struct OptimizedFieldConfig {
    /// 三个advice列用于不同的操作
    advice: [Column<Advice>; 3],
    /// instance列用于公开输出
    instance: Column<Instance>,
    /// fixed列用于常数
    constant: Column<Fixed>,
    /// 三个选择器用于不同的门
    s_add: Selector, // 加法门：a0 + a1 + a2 = next_row_a0
    s_mul: Selector, // 乘法门：a0 * a1 * const = a2
    s_sq: Selector,  // 平方门：a0 * a0 = next_row_a0
}

#[derive(Debug, Clone)]
struct OptimizedFieldChip<F: Field> {
    config: OptimizedFieldConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> OptimizedFieldChip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        OptimizedFieldChip {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        // 启用equality约束
        meta.enable_equality(instance);
        meta.enable_constant(constant);
        for c in &advice {
            meta.enable_equality(*c);
        }

        let s_add = meta.selector();
        let s_mul = meta.selector();
        let s_sq = meta.selector();

        // 加法门：a0 + a1 + a2 = next_row_a0
        meta.create_gate("add_gate", |meta| {
            let a0 = meta.query_advice(advice[0], Rotation::cur());
            let a1 = meta.query_advice(advice[1], Rotation::cur());
            let a2 = meta.query_advice(advice[2], Rotation::cur());
            let sum = meta.query_advice(advice[0], Rotation::next());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (a0 + a1 + a2 - sum)]
        });

        // 乘法门：a0 * a1 * const = a2
        meta.create_gate("mul_gate", |meta| {
            let a0 = meta.query_advice(advice[0], Rotation::cur());
            let a1 = meta.query_advice(advice[1], Rotation::cur());
            let a2 = meta.query_advice(advice[2], Rotation::cur());
            let const_val = meta.query_fixed(constant);
            let s_mul = meta.query_selector(s_mul);

            vec![s_mul * (a0 * a1 * const_val - a2)]
        });

        // 平方门：a0 * a0 = next_row_a0
        meta.create_gate("square_gate", |meta| {
            let a0 = meta.query_advice(advice[0], Rotation::cur());
            let a0_sq = meta.query_advice(advice[0], Rotation::next());
            let s_sq = meta.query_selector(s_sq);

            vec![s_sq * (a0.clone() * a0 - a0_sq)]
        });

        OptimizedFieldConfig {
            advice,
            instance,
            constant,
            s_add,
            s_mul,
            s_sq,
        }
    }
}

impl<F: Field> Chip<F> for OptimizedFieldChip<F> {
    type Config = OptimizedFieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Clone)]
struct Number<F: Field>(AssignedCell<F, F>);

impl<F: Field> OptimizedFieldChip<F> {
    /// 加载私有输入
    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<Number<F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| {
                region
                    .assign_advice(|| "private input", config.advice[0], 0, || value)
                    .map(Number)
            },
        )
    }

    /// 计算平方：a²
    fn square(&self, mut layouter: impl Layouter<F>, a: Number<F>) -> Result<Number<F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "square",
            |mut region| {
                config.s_sq.enable(&mut region, 0)?;
                a.0.copy_advice(|| "value", &mut region, config.advice[0], 0)?;

                let value_sq = a.0.value().map(|v| v.square());
                region
                    .assign_advice(|| "value²", config.advice[0], 1, || value_sq)
                    .map(Number)
            },
        )
    }

    /// 乘法运算：a × b × const
    fn mul_with_constant(
        &self,
        mut layouter: impl Layouter<F>,
        a: Number<F>,
        b: Number<F>,
        constant: F,
    ) -> Result<Number<F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "mul with constant",
            |mut region| {
                config.s_mul.enable(&mut region, 0)?;

                // 分配常数到fixed列
                region.assign_fixed(
                    || "constant",
                    config.constant,
                    0,
                    || Value::known(constant),
                )?;

                a.0.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "b", &mut region, config.advice[1], 0)?;

                let result =
                    a.0.value()
                        .zip(b.0.value())
                        .map(|(a_val, b_val)| *a_val * *b_val * constant);
                region
                    .assign_advice(|| "a×b×const", config.advice[2], 0, || result)
                    .map(Number)
            },
        )
    }

    /// 三数相加：a + b + c
    fn add_three(
        &self,
        mut layouter: impl Layouter<F>,
        a: Number<F>,
        b: Number<F>,
        c: Number<F>,
    ) -> Result<Number<F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add three",
            |mut region| {
                config.s_add.enable(&mut region, 0)?;

                a.0.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "b", &mut region, config.advice[1], 0)?;
                c.0.copy_advice(|| "c", &mut region, config.advice[2], 0)?;

                let sum =
                    a.0.value()
                        .zip(b.0.value())
                        .zip(c.0.value())
                        .map(|((a_val, b_val), c_val)| *a_val + *b_val + *c_val);

                region
                    .assign_advice(|| "a+b+c", config.advice[0], 1, || sum)
                    .map(Number)
            },
        )
    }

    /// 暴露公共输出
    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        num: Number<F>,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();
        layouter.constrain_instance(num.0.cell(), config.instance, row)
    }
}

#[derive(Default)]
struct OptimizedCircuit<F: Field> {
    constant: F,
    a: Value<F>,
    b: Value<F>,
}

impl<F: Field> Circuit<F> for OptimizedCircuit<F> {
    type Config = OptimizedFieldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        OptimizedFieldChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let field_chip = OptimizedFieldChip::<F>::construct(config);

        // 加载私有输入
        let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;

        // 计算 a² 和 b²
        let a_sq = field_chip.square(layouter.namespace(|| "a²"), a.clone())?;
        let b_sq = field_chip.square(layouter.namespace(|| "b²"), b.clone())?;

        // 计算 a × b × const
        let ab_const = field_chip.mul_with_constant(
            layouter.namespace(|| "a×b×const"),
            a,
            b,
            self.constant,
        )?;

        // 计算最终结果：a² + b² + (a×b×const)
        let result = field_chip.add_three(
            layouter.namespace(|| "a²+b²+ab×const"),
            a_sq,
            b_sq,
            ab_const,
        )?;

        // 暴露公共输出
        field_chip.expose_public(layouter.namespace(|| "expose result"), result, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    #[test]
    fn test_optimized_circuit() {
        let k = 6; // 稍微增大以容纳更多行

        // 准备输入
        let constant = Fp::from(3);
        let a = Fp::from(4);
        let b = Fp::from(5);

        // 计算期望输出：a² + b² + a×b×const = 16 + 25 + 60 = 101
        let expected_output = a.square() + b.square() + (a * b * constant);
        println!("Expected output: {:?}", expected_output);

        // 实例化电路
        let circuit = OptimizedCircuit {
            constant,
            a: Value::known(a),
            b: Value::known(b),
        };

        // 公共输入
        let public_inputs = vec![expected_output];

        // 验证电路
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // 测试错误的公共输入
        let wrong_public_inputs = vec![expected_output + Fp::one()];
        let prover = MockProver::run(k, &circuit, vec![wrong_public_inputs]).unwrap();
        assert!(prover.verify().is_err());

        println!("优化电路测试通过！");
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn test_optimized_circuit_visual() {
        use plotters::prelude::*;

        let k = 6;
        let constant = Fp::from(3);
        let a = Fp::from(4);
        let b = Fp::from(5);

        let circuit = OptimizedCircuit {
            constant,
            a: Value::known(a),
            b: Value::known(b),
        };

        // 创建可视化
        let root =
            BitMapBackend::new("./images/simple_chip_opt.png", (1200, 800)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Optimized Simple Chip Circuit", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(k, &circuit, &root)
            .unwrap();

        println!("电路可视化已生成: ./images/basic_middle.png");
    }
}
