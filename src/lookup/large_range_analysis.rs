/// ==============================================
/// 方案对比分析
/// ==============================================
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::group::ff::PrimeField,
    plonk::*,
    poly::Rotation,
};
/// 大范围查找表的具体实现方案
/// 1. 位分解 + 小范围Lookup：适合中等范围 (如2^24)
/// 2. 二进制约束：适合大范围 (如2^32)
use std::marker::PhantomData;

/// ==============================================
/// 方案1：位分解 + 小范围Lookup
/// 将32位数分解为4个8位字节，每个字节用256项的lookup table验证
/// ==============================================

#[derive(Debug, Clone)]
struct BitDecompositionConfig<F: PrimeField> {
    // 存储原始值和分解后的字节
    value: Column<Advice>,
    bytes: [Column<Advice>; 4], // 4个8位字节
    // 小范围lookup table (0-255)
    byte_table: TableColumn,
    // 选择器
    s_decomp: Selector, // 位分解约束
    s_lookup: Selector, // lookup约束
    _marker: PhantomData<F>,
}

impl<F: PrimeField> BitDecompositionConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        value: Column<Advice>,
        bytes: [Column<Advice>; 4],
        byte_table: TableColumn,
    ) -> Self {
        let s_decomp = meta.selector();
        let s_lookup = meta.complex_selector();

        // 启用equality约束
        meta.enable_equality(value);
        for col in bytes.iter() {
            meta.enable_equality(*col);
        }

        // 位分解约束：确保 value = byte0 + byte1*256 + byte2*256² + byte3*256³
        meta.create_gate("bit_decomposition", |meta| {
            let s_decomp = meta.query_selector(s_decomp);
            let value = meta.query_advice(value, Rotation::cur());
            let byte0 = meta.query_advice(bytes[0], Rotation::cur());
            let byte1 = meta.query_advice(bytes[1], Rotation::cur());
            let byte2 = meta.query_advice(bytes[2], Rotation::cur());
            let byte3 = meta.query_advice(bytes[3], Rotation::cur());

            // value = byte0 + byte1*256 + byte2*256² + byte3*256³
            let decomposition = byte0
                + byte1 * Expression::Constant(F::from(256))
                + byte2 * Expression::Constant(F::from(256 * 256))
                + byte3 * Expression::Constant(F::from(256 * 256 * 256));

            vec![s_decomp * (value - decomposition)]
        });

        // 每个字节的lookup约束：确保每个字节在[0,255]范围内
        for &col in bytes.iter() {
            meta.lookup(|meta| {
                let s_lookup = meta.query_selector(s_lookup);
                let byte_val = meta.query_advice(col, Rotation::cur());
                vec![(s_lookup * byte_val, byte_table)]
            });
        }

        BitDecompositionConfig {
            value,
            bytes,
            byte_table,
            s_decomp,
            s_lookup,
            _marker: PhantomData,
        }
    }

    /// 加载256个值的小lookup table
    fn load_byte_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "load 8-bit lookup table",
            |mut table| {
                for value in 0..256u64 {
                    table.assign_cell(
                        || "byte table cell",
                        self.byte_table,
                        value as usize,
                        || Value::known(F::from(value)),
                    )?;
                }
                Ok(())
            },
        )
    }

    /// 分配值并进行位分解验证
    fn assign_and_decompose(
        &self,
        mut layouter: impl Layouter<F>,
        value: u32,
    ) -> Result<AssignedCell<F, F>, Error> {
        // 分解为4个字节
        let byte0 = (value & 0xFF) as u8;
        let byte1 = ((value >> 8) & 0xFF) as u8;
        let byte2 = ((value >> 16) & 0xFF) as u8;
        let byte3 = ((value >> 24) & 0xFF) as u8;

        layouter.assign_region(
            || "bit decomposition",
            |mut region| {
                // 启用选择器
                self.s_decomp.enable(&mut region, 0)?;
                self.s_lookup.enable(&mut region, 0)?;

                // 分配原始值
                let value_cell = region.assign_advice(
                    || "value",
                    self.value,
                    0,
                    || Value::known(F::from(value as u64)),
                )?;

                // 分配分解后的字节
                region.assign_advice(
                    || "byte0",
                    self.bytes[0],
                    0,
                    || Value::known(F::from(byte0 as u64)),
                )?;
                region.assign_advice(
                    || "byte1",
                    self.bytes[1],
                    0,
                    || Value::known(F::from(byte1 as u64)),
                )?;
                region.assign_advice(
                    || "byte2",
                    self.bytes[2],
                    0,
                    || Value::known(F::from(byte2 as u64)),
                )?;
                region.assign_advice(
                    || "byte3",
                    self.bytes[3],
                    0,
                    || Value::known(F::from(byte3 as u64)),
                )?;

                Ok(value_cell)
            },
        )
    }
}

/// ==============================================
/// 方案2：二进制约束
/// 使用二进制位分解进行大范围检查，不需要lookup table
/// ==============================================

#[derive(Debug, Clone)]
struct BinaryRangeConfig<F: PrimeField> {
    value: Column<Advice>,
    // 二进制位表示
    bits: [Column<Advice>; 32], // 32位二进制
    s_binary: Selector,
    s_composition: Selector,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> BinaryRangeConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        value: Column<Advice>,
        bits: [Column<Advice>; 32],
    ) -> Self {
        let s_binary = meta.selector();
        let s_composition = meta.selector();

        // 启用equality约束
        meta.enable_equality(value);
        for col in bits.iter() {
            meta.enable_equality(*col);
        }

        // 二进制约束：确保每一位都是0或1
        for (i, &bit_col) in bits.iter().enumerate() {
            meta.create_gate("binary_constraint", |meta| {
                let s_binary = meta.query_selector(s_binary);
                let bit = meta.query_advice(bit_col, Rotation::cur());

                // bit * (bit - 1) = 0，确保bit ∈ {0, 1}
                vec![s_binary * bit.clone() * (bit - Expression::Constant(F::ONE))]
            });
        }

        // 组合约束：确保 value = Σ(bit_i * 2^i)
        meta.create_gate("composition_constraint", |meta| {
            let s_composition = meta.query_selector(s_composition);
            let value = meta.query_advice(value, Rotation::cur());

            let mut composition = Expression::Constant(F::ZERO);
            for (i, &bit_col) in bits.iter().enumerate() {
                let bit = meta.query_advice(bit_col, Rotation::cur());
                let power_of_two = F::from(1u64 << i);
                composition = composition + bit * Expression::Constant(power_of_two);
            }

            vec![s_composition * (value - composition)]
        });

        BinaryRangeConfig {
            value,
            bits,
            s_binary,
            s_composition,
            _marker: PhantomData,
        }
    }

    /// 分配值并进行二进制分解验证
    fn assign_and_decompose(
        &self,
        mut layouter: impl Layouter<F>,
        value: u32,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "binary decomposition",
            |mut region| {
                // 启用选择器
                self.s_binary.enable(&mut region, 0)?;
                self.s_composition.enable(&mut region, 0)?;

                // 分配原始值
                let value_cell = region.assign_advice(
                    || "value",
                    self.value,
                    0,
                    || Value::known(F::from(value as u64)),
                )?;

                // 分解为32个二进制位
                for i in 0..32 {
                    let bit = (value >> i) & 1;
                    region.assign_advice(
                        || "bit",
                        self.bits[i],
                        0,
                        || Value::known(F::from(bit as u64)),
                    )?;
                }

                Ok(value_cell)
            },
        )
    }
}

/// ==============================================
/// 测试电路：位分解方案
/// ==============================================

#[derive(Default)]
struct BitDecompositionCircuit<F: PrimeField> {
    value: u32,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for BitDecompositionCircuit<F> {
    type Config = BitDecompositionConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let value = meta.advice_column();
        let bytes = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let byte_table = meta.lookup_table_column();

        BitDecompositionConfig::configure(meta, value, bytes, byte_table)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // 加载lookup table
        config.load_byte_table(&mut layouter)?;

        // 验证值的范围
        config.assign_and_decompose(layouter.namespace(|| "decompose"), self.value)?;

        Ok(())
    }
}

/// ==============================================
/// 测试电路：二进制约束方案
/// ==============================================

#[derive(Default)]
struct BinaryRangeCircuit<F: PrimeField> {
    value: u32,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for BinaryRangeCircuit<F> {
    type Config = BinaryRangeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let value = meta.advice_column();
        let mut bits = Vec::new();
        for _ in 0..32 {
            bits.push(meta.advice_column());
        }
        let bits: [Column<Advice>; 32] = bits.try_into().unwrap();

        BinaryRangeConfig::configure(meta, value, bits)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // 验证值的范围
        config.assign_and_decompose(layouter.namespace(|| "binary_decompose"), self.value)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    #[test]
    fn test_bit_decomposition_range_check() {
        let k = 10;

        // 测试一个在2^32范围内的值
        let test_value = 0x12345678u32; // 305419896

        let circuit = BitDecompositionCircuit::<Fp> {
            value: test_value,
            _marker: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        println!(
            "位分解方案测试通过！值: 0x{:08X} = {}",
            test_value, test_value
        );
    }

    #[test]
    fn test_binary_range_check() {
        let k = 10;

        // 测试一个2^32范围内的值
        let test_value = 0xFFFFFFFFu32; // 最大32位值

        let circuit = BinaryRangeCircuit::<Fp> {
            value: test_value,
            _marker: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        println!(
            "二进制约束方案测试通过！值: 0x{:08X} = {}",
            test_value, test_value
        );
    }
}
