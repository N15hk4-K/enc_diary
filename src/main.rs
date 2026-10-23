use std::env; //to read the command line arguments passed to the program

mod func;

fn main() {
    let args: Vec<String> = env::args().collect(); //args() returns an iterator of the command line
                                                   //arguments passed to it; collect method turns
                                                   //an iterator into a collection
    dbg!(&args); //to print the args
    println!("{:?}",args); //have to do it like this cuz vector doesn't implement the Display trait
    if args.len()!=3 {
        eprintln!("Usage: enc-diary <decrypt/encrypt/edit> <file_path>"); // prints to stderr
        return; // std::process:exit(1) terminates the entire process immediately without running
                // any destructors
    }
    let res: Result<(), String> = match args[1].as_str() { // args[1] is a String, we are comparing it with str values
        "decrypt" => {
            println!("You typed decrypt!");
            func::decrypt_this(&args[2])
        }
        "encrypt" => {
            println!("You typed encrypt!");
            func::encrypt_this(&args[2])
        }
        "edit" => {
            println!("You typed edit!");
            func::call_editor(&args[2])
        }
        _ => {
            Err("Usage: enc-diary <decrypt/encrypt/edit> <file_path>".to_string())
        }
    };
    match res {
        Ok(()) => return,
        Err(err) => eprintln!("{}",err),
    };
}
