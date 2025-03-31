use std::fs::OpenOptions;
use std::io::{self, Read, Write, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};
use std::f64::consts::PI;

const TIMEOUT_MS: u64 = 3; // Timeout in Millisekunden
const NUM_POINTS: usize = 700; // Anzahl der Punkte
const RADIUS: f64 = 10.0; // Radius des Kreises

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    
    // Array zur Speicherung der (x, y) Koordinaten
    let mut points = Vec::with_capacity(NUM_POINTS);
    let mut latency = Vec::with_capacity(NUM_POINTS);
  
    if let Ok(n) = stream.read(&mut buffer) {
        let msg = String::from_utf8_lossy(&buffer[..n]);
        if msg.trim() == "start" {
            println!("Berechnung gestartet...");
            let mut last_y = 0.0;
	    let mut duration = Duration::ZERO;
            
            // Berechnung aller Punkte
            for i in 0..NUM_POINTS {
                let theta = 2.0 * PI * (i as f64) / (NUM_POINTS as f64);
                let x = RADIUS * theta.cos();
                let start_time = Instant::now();
                
                if let Err(e) = stream.write_all(format!("{} {}\n", theta, RADIUS).as_bytes()) {
                    eprintln!("Fehler beim Senden: {}", e);
                    return;
                }
                
                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        duration = start_time.elapsed();
                        //println!("Nachricht Ok");
                        
                        if duration.as_millis() > TIMEOUT_MS as u128 {
                            println!("Timeout überschritten, alter y-Wert verwendet");
                        } else {
                            if let Ok(y) = String::from_utf8_lossy(&buffer[..n]).trim().parse::<f64>() {
                                last_y = y;
                            }
                        }
                    }
                    _ => println!("Fehler beim Empfang oder keine Antwort erhalten"),
                }
                
                // Speichern der x und y Werte im Array
                points.push((x, last_y));
		latency.push(duration.as_nanos());
            }

            // Schreiben der berechneten Punkte in die Datei nach der gesamten Berechnung
            let mut circle_points = BufWriter::new(OpenOptions::new().write(true).create(true).open("../circle_points").unwrap());
	    let mut latencies = BufWriter::new(OpenOptions::new().write(true).create(true).open("../latencys").unwrap());

            for (x, y) in points {
                writeln!(circle_points, "{},{}", x, y).unwrap();
            }
	    
	    for l in latency {
		writeln!(latencies, "{}", l).unwrap();
	    }

            circle_points.flush().unwrap();
	    latencies.flush().unwrap();

            println!("Points and Latencies written.");
        }
    }
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("192.168.1.1:8080")?;
    println!("Server läuft auf 192.168.1.1:8080");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(e) => eprintln!("Verbindungsfehler: {}", e),
        }
    }
    Ok(())
}
