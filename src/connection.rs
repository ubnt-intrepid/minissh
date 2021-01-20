pub struct Connection {
    _p: (),
}

impl Connection {
    pub(crate) fn new() -> Self {
        Self { _p: () }
    }
}
