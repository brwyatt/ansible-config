use shotover::runner::Shotover;

mod redis_prefix_rewrite;
shotover::import_transform!(redis_prefix_rewrite::RedisPrefixRewriteConfig);

fn main() {
    Shotover::new().run_block();
}
