use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

/// 示例：实现一个简单的平方和芯片
/// 功能：计算 a² + b² = c

// 1️⃣ 定义配置结构
#[derive(Debug, Clone)]
struct SquareSumConfig {
    advice: [Column<Advice>; 3], // 3个advice列
    instance: Column<Instance>,  // 实例列
    s_square: Selector,          // 平方选择器
    s_add: Selector,             // 加法选择器
}

// 2️⃣ 定义芯片结构
#[derive(Debug, Clone)]
struct SquareSumChip<F: Field> {
    config: SquareSumConfig,
    _marker: PhantomData<F>,
}

// 3️⃣ 实现Chip trait (必须实现的接口)
impl<F: Field> Chip<F> for SquareSumChip<F> {
    type Config = SquareSumConfig; // 关联配置类型
    type Loaded = (); // 加载状态类型

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

// 4️⃣ 实现芯片的核心功能
impl<F: Field> SquareSumChip<F> {
    /// 构造函数
    fn construct(config: SquareSumConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    /// 配置函数 - 定义电路约束
    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> SquareSumConfig {
        // 启用equality约束
        meta.enable_equality(instance);
        for c in &advice {
            meta.enable_equality(*c);
        }

        let s_square = meta.selector();
        let s_add = meta.selector();

        // 创建平方门: a * a = a²
        meta.create_gate("square", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let a_squared = meta.query_advice(advice[1], Rotation::cur());
            let s_square = meta.query_selector(s_square);

            vec![s_square * (a.clone() * a - a_squared)]
        });

        // 创建加法门: a + b = c
        meta.create_gate("add", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (a + b - c)]
        });

        SquareSumConfig {
            advice,
            instance,
            s_square,
            s_add,
        }
    }

    /// 加载私有输入
    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| region.assign_advice(|| "private input", config.advice[0], 0, || value),
        )
    }

    /// 计算平方: a²
    fn square(
        &self,
        mut layouter: impl Layouter<F>,
        value: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "square",
            |mut region| {
                config.s_square.enable(&mut region, 0)?;

                value.copy_advice(|| "value", &mut region, config.advice[0], 0)?;

                let value_squared = value.value().map(|v| v.square());
                region.assign_advice(|| "value²", config.advice[1], 0, || value_squared)
            },
        )
    }

    /// 加法运算: a + b = c
    fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: AssignedCell<F, F>,
        b: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add",
            |mut region| {
                config.s_add.enable(&mut region, 0)?;

                a.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "b", &mut region, config.advice[1], 0)?;

                let sum = a.value().zip(b.value()).map(|(a, b)| *a + *b);
                region.assign_advice(|| "a + b", config.advice[2], 0, || sum)
            },
        )
    }

    /// 暴露公共输出
    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();
        layouter.constrain_instance(cell.cell(), config.instance, row)
    }
}

// 5️⃣ 定义电路结构
#[derive(Default)]
struct SquareSumCircuit<F: Field> {
    a: Value<F>,
    b: Value<F>,
}

// 6️⃣ 实现Circuit trait (必须实现的接口)
impl<F: Field> Circuit<F> for SquareSumCircuit<F> {
    type Config = SquareSumConfig; // 配置类型
    type FloorPlanner = SimpleFloorPlanner; // 布局规划器

    /// 创建无witness的电路实例 (用于密钥生成)
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    /// 配置电路结构和约束
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();

        SquareSumChip::configure(meta, advice, instance)
    }

    /// 实现电路的具体计算逻辑
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // 构造芯片实例
        let chip = SquareSumChip::construct(config);

        // 步骤1: 加载私有输入
        let a = chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = chip.load_private(layouter.namespace(|| "load b"), self.b)?;

        // 步骤2: 计算平方
        let a_squared = chip.square(layouter.namespace(|| "a²"), a)?;
        let b_squared = chip.square(layouter.namespace(|| "b²"), b)?;

        // 步骤3: 计算和
        let result = chip.add(layouter.namespace(|| "a² + b²"), a_squared, b_squared)?;

        // 步骤4: 暴露公共输出
        chip.expose_public(layouter.namespace(|| "expose result"), result, 0)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    #[test]
    fn test_square_sum_circuit() {
        let k = 4;

        // 准备输入: a = 3, b = 4
        let a = Fp::from(3);
        let b = Fp::from(4);
        let c = a.square() + b.square(); // 9 + 16 = 25

        // 创建电路实例
        let circuit = SquareSumCircuit {
            a: Value::known(a),
            b: Value::known(b),
        };

        // 公共输入
        let public_inputs = vec![c];

        // 验证电路
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // 测试错误的公共输入
        let wrong_public_inputs = vec![c + Fp::one()];
        let prover = MockProver::run(k, &circuit, vec![wrong_public_inputs]).unwrap();
        assert!(prover.verify().is_err());

        println!("平方和电路测试通过！");
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn test_square_sum_visual() {
        use plotters::prelude::*;

        let k = 4;
        let circuit = SquareSumCircuit {
            a: Value::known(Fp::from(3)),
            b: Value::known(Fp::from(4)),
        };

        let root = BitMapBackend::new("./images/square_sum_interface_example.png", (1024, 768))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Square Sum Interface Example", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(true)
            .render(k, &circuit, &root)
            .unwrap();

        println!("电路可视化已生成: ./images/basic_chip.png");
    }
}
