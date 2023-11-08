use crate::minecraft::MinecraftSlp;

/// Stores the results of a scan
pub trait Storage {
    type StoreResult;

    fn store(&mut self, ip: [u8; 4], packet: MinecraftSlp);
    fn finalize(&mut self) -> Self::StoreResult;
}

/// Default store - just prints the result

pub struct TestStore(pub Vec<([u8;4], MinecraftSlp)>);

impl Storage for TestStore {
    type StoreResult = Result<(), !>;

    fn store(&mut self, ip: [u8;4], packet: MinecraftSlp) {
        self.0.push((ip, packet));
    }

    fn finalize(&mut self) -> Self::StoreResult {
        println!("{:?}", self.0);
        Ok(())
    }
}
