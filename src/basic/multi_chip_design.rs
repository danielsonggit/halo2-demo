use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};

/// ==============================================
/// 1. 平方Chip - 专门处理平方运算
/// ==============================================

#[derive(Debug, Clone)]
struct SquareConfig {
    advice: [Column<Advice>; 2], // [input, output]
    s_square: Selector,
}

#[derive(Debug, Clone)]
struct SquareChip<F: Field> {
    config: SquareConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for SquareChip<F> {
    type Config = SquareConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> SquareChip<F> {
    fn construct(config: SquareConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>, advice: [Column<Advice>; 2]) -> SquareConfig {
        let s_square = meta.selector();

        // 启用equality约束
        for c in &advice {
            meta.enable_equality(*c);
        }

        // 平方门：input * input = output
        meta.create_gate("square_gate", |meta| {
            let input = meta.query_advice(advice[0], Rotation::cur());
            let output = meta.query_advice(advice[1], Rotation::cur());
            let s_square = meta.query_selector(s_square);

            vec![s_square * (input.clone() * input - output)]
        });

        SquareConfig { advice, s_square }
    }

    /// 计算平方：input² = output
    fn square(
        &self,
        mut layouter: impl Layouter<F>,
        input: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "square operation",
            |mut region| {
                config.s_square.enable(&mut region, 0)?;

                input.copy_advice(|| "input", &mut region, config.advice[0], 0)?;

                let output_value = input.value().map(|v| v.square());
                region.assign_advice(|| "input²", config.advice[1], 0, || output_value)
            },
        )
    }
}

/// ==============================================
/// 2. 加法Chip - 专门处理加法运算
/// ==============================================

#[derive(Debug, Clone)]
struct AddConfig {
    advice: [Column<Advice>; 4], // [a, b, c, sum]
    s_add: Selector,
}

#[derive(Debug, Clone)]
struct AddChip<F: Field> {
    config: AddConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for AddChip<F> {
    type Config = AddConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> AddChip<F> {
    fn construct(config: AddConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>, advice: [Column<Advice>; 4]) -> AddConfig {
        let s_add = meta.selector();

        // 启用equality约束
        for c in &advice {
            meta.enable_equality(*c);
        }

        // 三数相加门：a + b + c = sum
        meta.create_gate("add_three_gate", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            let sum = meta.query_advice(advice[3], Rotation::cur());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (a + b + c - sum)]
        });

        AddConfig { advice, s_add }
    }

    /// 三数相加：a + b + c = sum
    fn add_three(
        &self,
        mut layouter: impl Layouter<F>,
        a: AssignedCell<F, F>,
        b: AssignedCell<F, F>,
        c: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add three numbers",
            |mut region| {
                config.s_add.enable(&mut region, 0)?;

                a.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "b", &mut region, config.advice[1], 0)?;
                c.copy_advice(|| "c", &mut region, config.advice[2], 0)?;

                let sum_value = a
                    .value()
                    .zip(b.value())
                    .zip(c.value())
                    .map(|((a_val, b_val), c_val)| *a_val + *b_val + *c_val);

                region.assign_advice(|| "a+b+c", config.advice[3], 0, || sum_value)
            },
        )
    }
}

/// ==============================================
/// 3. 乘法Chip - 专门处理乘法运算
/// ==============================================

#[derive(Debug, Clone)]
struct MulConfig {
    advice: [Column<Advice>; 3], // [a, b, product]
    constant: Column<Fixed>,
    s_mul: Selector,
}

#[derive(Debug, Clone)]
struct MulChip<F: Field> {
    config: MulConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for MulChip<F> {
    type Config = MulConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> MulChip<F> {
    fn construct(config: MulConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        constant: Column<Fixed>,
    ) -> MulConfig {
        let s_mul = meta.selector();

        // 启用equality和constant约束
        meta.enable_constant(constant);
        for c in &advice {
            meta.enable_equality(*c);
        }

        // 乘法门：a * b * constant = product
        meta.create_gate("mul_with_constant_gate", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let product = meta.query_advice(advice[2], Rotation::cur());
            let constant = meta.query_fixed(constant);
            let s_mul = meta.query_selector(s_mul);

            vec![s_mul * (a * b * constant - product)]
        });

        MulConfig {
            advice,
            constant,
            s_mul,
        }
    }

    /// 乘法运算：a × b × constant = product
    fn mul_with_constant(
        &self,
        mut layouter: impl Layouter<F>,
        a: AssignedCell<F, F>,
        b: AssignedCell<F, F>,
        constant: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "multiply with constant",
            |mut region| {
                config.s_mul.enable(&mut region, 0)?;

                // 分配常数
                region.assign_fixed(
                    || "constant",
                    config.constant,
                    0,
                    || Value::known(constant),
                )?;

                a.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "b", &mut region, config.advice[1], 0)?;

                let product_value = a
                    .value()
                    .zip(b.value())
                    .map(|(a_val, b_val)| *a_val * *b_val * constant);

                region.assign_advice(|| "a×b×const", config.advice[2], 0, || product_value)
            },
        )
    }
}

/// ==============================================
/// 4. 组合配置 - 整合三个Chip
/// ==============================================

#[derive(Debug, Clone)]
struct MultiChipConfig {
    square_config: SquareConfig,
    add_config: AddConfig,
    mul_config: MulConfig,
    instance: Column<Instance>,
}

/// ==============================================
/// 5. 多Chip电路 - 使用三个独立的Chip
/// ==============================================

#[derive(Default)]
struct MultiChipCircuit<F: Field> {
    constant: F,
    a: Value<F>,
    b: Value<F>,
}

impl<F: Field> Circuit<F> for MultiChipCircuit<F> {
    type Config = MultiChipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // 为平方chip分配列
        let square_advice = [meta.advice_column(), meta.advice_column()];
        let square_config = SquareChip::configure(meta, square_advice);

        // 为加法chip分配列
        let add_advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let add_config = AddChip::configure(meta, add_advice);

        // 为乘法chip分配列
        let mul_advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let mul_constant = meta.fixed_column();
        let mul_config = MulChip::configure(meta, mul_advice, mul_constant);

        MultiChipConfig {
            square_config,
            add_config,
            mul_config,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // 构造三个独立的chip
        let square_chip = SquareChip::construct(config.square_config.clone());
        let add_chip = AddChip::construct(config.add_config.clone());
        let mul_chip = MulChip::construct(config.mul_config.clone());

        // 创建临时的advice列用于加载输入
        let temp_advice = config.square_config.advice[0];

        // 加载私有输入
        let a = layouter.assign_region(
            || "load a",
            |mut region| region.assign_advice(|| "private input a", temp_advice, 0, || self.a),
        )?;

        let b = layouter.assign_region(
            || "load b",
            |mut region| region.assign_advice(|| "private input b", temp_advice, 0, || self.b),
        )?;

        // 🔷 使用平方chip计算 a² 和 b²
        let a_squared = square_chip.square(layouter.namespace(|| "compute a²"), a.clone())?;
        let b_squared = square_chip.square(layouter.namespace(|| "compute b²"), b.clone())?;

        // 🔶 使用乘法chip计算 a × b × constant
        let ab_const = mul_chip.mul_with_constant(
            layouter.namespace(|| "compute a×b×const"),
            a,
            b,
            self.constant,
        )?;

        // 🔹 使用加法chip计算最终结果: a² + b² + (a×b×const)
        let result = add_chip.add_three(
            layouter.namespace(|| "compute final sum"),
            a_squared,
            b_squared,
            ab_const,
        )?;

        // 暴露公共输出
        layouter.constrain_instance(result.cell(), config.instance, 0)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    #[test]
    fn test_multi_chip_circuit() {
        let k = 8; // 增大以容纳更多chip的运算

        // 准备输入
        let constant = Fp::from(3);
        let a = Fp::from(4);
        let b = Fp::from(5);

        // 计算期望输出：a² + b² + a×b×const = 16 + 25 + 60 = 101
        let expected_output = a.square() + b.square() + (a * b * constant);
        println!("🧮 计算过程：");
        println!("   a = {}, b = {}, const = {}", 4, 5, 3);
        println!("   a² = {}", 16);
        println!("   b² = {}", 25);
        println!("   a×b×const = {}×{}×{} = {}", 4, 5, 3, 60);
        println!("   final = 16 + 25 + 60 = {}", 101);
        println!("   expected_output = {:?}", expected_output);

        // 实例化电路
        let circuit = MultiChipCircuit {
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

        println!("多Chip电路测试通过！");
        println!("平方Chip: 计算 a² 和 b²");
        println!("乘法Chip: 计算 a×b×constant");
        println!("加法Chip: 计算最终求和");
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn test_multi_chip_visual() {
        use plotters::prelude::*;

        let k = 8;
        let constant = Fp::from(3);
        let a = Fp::from(4);
        let b = Fp::from(5);

        let circuit = MultiChipCircuit {
            constant,
            a: Value::known(a),
            b: Value::known(b),
        };

        // 创建可视化
        let root =
            BitMapBackend::new("./images/multi_chip_design.png", (1400, 1000)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Multi-Chip Modular Design", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(k, &circuit, &root)
            .unwrap();

        println!("多Chip电路可视化已生成: ./images/multi_chip_design.png");
    }
}
