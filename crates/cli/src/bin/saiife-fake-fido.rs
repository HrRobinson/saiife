//! A scripted FIDO helper for tests (feature `fake-fido`): see `saiife_fido::fake`.

fn main() -> std::process::ExitCode {
    saiife_fido::fake::main()
}
