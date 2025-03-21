use sp1_helper::{build_program_with_args, BuildArgs};

const MINNOW_H_ELF_NAME: &str = "../elf/minnow-h-program";
const MINNOW_MT_ELF_NAME: &str = "../elf/minnow-mt-program";

fn main() {
    build_program_with_args(
        "../minnow-h-program",
        BuildArgs {
            elf_name: MINNOW_H_ELF_NAME.to_string(),
            ..Default::default()
        },
    );
    build_program_with_args(
        "../minnow-mt-program",
        BuildArgs {
            elf_name: MINNOW_MT_ELF_NAME.to_string(),
            ..Default::default()
        },
    );
}
