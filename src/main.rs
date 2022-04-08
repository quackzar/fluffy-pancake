use std::thread;
use ductile::new_local_channel;
use magic_pake::fpake::OneOfManyKey;

fn main() {
    const NUMBER_OF_PASSWORDS: usize = 4096;
    let passwords = vec![vec![0u8; 2048 / 8]; NUMBER_OF_PASSWORDS as usize];
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
        let _ = OneOfManyKey::garbler_server(&passwords, threshold, &ch1).unwrap();
    });

    let h2 = thread::spawn(move || {
        // Party 1
        let _ = OneOfManyKey::evaluator_client(
            &password_2,
            NUMBER_OF_PASSWORDS as u32,
            index,
            &ch2,
        ).unwrap();
    });

    let _k1 = h1.join().unwrap();
    let _k2 = h2.join().unwrap();
}

