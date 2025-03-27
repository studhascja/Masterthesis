use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::process;

fn main() -> io::Result<()> {
    // Versuche, eine Verbindung zum Server (z.B. auf localhost und Port 8080) herzustellen
    let server_address = "192.168.1.1:8080"; // Ersetze durch die IP-Adresse deines Raspberry Pi, wenn notwendig
    match TcpStream::connect(server_address) {
        Ok(mut stream) => {
            println!("Mit Server verbunden: {}", server_address);

            // Nachricht an den Server senden
            let message = "Hallo, Server!";
            stream.write_all(message.as_bytes())?;

            println!("Nachricht gesendet: {}", message);

            // Antwort vom Server empfangen
            let mut buffer = [0; 1024];
            let size = stream.read(&mut buffer)?;

            if size > 0 {
                let response = String::from_utf8_lossy(&buffer[..size]);
                println!("Antwort vom Server: {}", response);
            }
        }
        Err(e) => {
            eprintln!("Fehler bei der Verbindung zum Server: {}", e);
            process::exit(1);
        }
    }

    Ok(())
}

