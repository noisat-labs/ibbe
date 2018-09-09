use rand::{ Rng, Rand };
use sha3::{ Shake256, Sha3XofReader };
use digest::{ Input, ExtendableOutput, XofReader };
use byteorder::{ ByteOrder, LittleEndian };
use pairing::bls12_381::Fr;


struct HashRng(Sha3XofReader);

impl HashRng {
    fn new<A: AsRef<[u8]>>(value: A) -> HashRng {
        let mut hasher = Shake256::default();
        hasher.process(value.as_ref());
        HashRng(hasher.xof_result())
    }
}

impl Rng for HashRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        LittleEndian::read_u32(&bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        LittleEndian::read_u64(&bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest)
    }
}

pub fn str_to_fr(id: &str) -> Fr {
    let mut rng = HashRng::new(id);
    Fr::rand(&mut rng)
}
