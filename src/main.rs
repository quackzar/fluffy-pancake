use ductile::new_local_channel;
use magic_pake::fpake::OneOfManyKey;
use std::thread;

fn main() {
    let number_of_passwords = 1 << 8;
    let passwords = vec![vec![0u8; 2048 / 8]; number_of_passwords as usize];
    let passwords_2 = passwords.clone();
    let index = 1;
    let password = passwords[index as usize].clone();
    let password_2 = password.clone();
    let threshold = 0;

    // Do the thing
    let (s1, r1) = new_local_channel();
    let (s2, r2) = new_local_channel();
    let ch1 = (s2, r1);
    let ch2 = (s1, r2);

    let h1 = thread::spawn(move || {
        // Party 1
        let k1 = OneOfManyKey::garbler_server(&passwords, threshold, &ch1).unwrap();
        let k2 = OneOfManyKey::evaluator_server(&passwords_2, &ch1).unwrap();
        k1.combine(k2);
    });

    let h2 = thread::spawn(move || {
        // Party 1
        let k1 =
            OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2).unwrap();

        let k2 =
            OneOfManyKey::garbler_client(&password, index, number_of_passwords, threshold, &ch2)
                .unwrap();
        k1.combine(k2);
    });

    let _k1 = h1.join().unwrap();
    let _k2 = h2.join().unwrap();
}
