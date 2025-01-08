pub fn init_logging(level: log::LevelFilter) {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(level);
    builder.try_init().unwrap();
}
