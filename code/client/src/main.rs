use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::process;
use std::f64::consts::PI;
use std::{thread, time};

fn main() -> io::Result<()> {
    let server_address = "192.168.1.1:8080";
    match TcpStream::connect(server_address) {
        Ok(mut stream) => {
            println!("Mit Server verbunden: {}", server_address);
            
            // Startsignal an den Server senden
            stream.write_all(b"start\n")?;
            
            let mut buffer = [0; 1024];
            while let Ok(size) = stream.read(&mut buffer) {
                if size == 0 {
                    break; // Verbindung geschlossen
                }
                
                let received_str = String::from_utf8_lossy(&buffer[..size]).trim().to_string();
                let parts: Vec<&str> = received_str.split_whitespace().collect();
                
                if parts.len() == 2 {
                    if let (Ok(theta), Ok(radius)) = (parts[0].parse::<f64>(), parts[1].parse::<f64>()) {
                        let y = radius * theta.sin(); // Berechnung von y aus theta
                        let y_str = format!("{}\n", y);
                        // thread::sleep(time::Duration::from_millis(10)); 
                        if let Err(e) = stream.write_all(y_str.as_bytes()) {
                            eprintln!("Fehler beim Senden der y-Koordinate: {}", e);
                            break;
                        }
                    }
                } else {
                    eprintln!("Ungültige Daten empfangen: {}", received_str);
                }
            }
        }
        Err(e) => {
            eprintln!("Fehler bei der Verbindung zum Server: {}", e);
            process::exit(1);
        }
    }

    Ok(())
}

