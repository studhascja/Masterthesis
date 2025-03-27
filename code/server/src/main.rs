use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    
    // Lese die Daten, die der Client sendet
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // Verbindung wurde geschlossen
            Ok(n) => {
                let msg = String::from_utf8_lossy(&buffer[..n]);
                println!("Nachricht empfangen: {}", msg);
                
                // Sende eine Antwort an den Client
                if let Err(e) = stream.write_all(b"Nachricht empfangen\n") {
                    eprintln!("Fehler beim Senden der Antwort: {}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Fehler beim Lesen der Daten: {}", e);
                break;
            }
        }
    }
}

fn main() -> io::Result<()> {
    // Server hört auf Port 8080 (du kannst den Port nach Bedarf ändern)
    let listener = TcpListener::bind("192.168.1.1:8080")?;
    println!("Server läuft und hört auf Port 8080");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Wenn ein Client eine Verbindung aufbaut, wird ein neuer Thread gestartet
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Fehler beim Akzeptieren der Verbindung: {}", e);
            }
        }
    }

    Ok(())
}

