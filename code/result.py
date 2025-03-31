import pygame
import sys

bar_scale = 400
x_offset = 350

def read_points(filename):
    points = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                try:
                    x, y = map(float, line.strip().split(','))
                    points.append((int(x * 15 + 1500), int(-y * 15 + 200)))
                except ValueError:
                    print(f"Fehlerhafte Zeile: {line.strip()}")
    except FileNotFoundError:
        print("Datei nicht gefunden!")
    return points

def read_latencies(filename):
    latencies = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                try:
                    latency = float(line.strip())  
                    latencies.append(latency)
                except ValueError:
                    print(f"Fehlerhafte Zeile: {line.strip()}")
    except FileNotFoundError:
        print("Datei mit Latenzen nicht gefunden!")
    return latencies

def calculate_latency_statistics(latencies):
    if not latencies:
        return None, None, None, None, None
    
    avg_latency = round((sum(latencies) / len(latencies)) / 1_000_000, 3)
    min_latency = round(min(latencies) / 1_000_000, 3)
    max_latency = round (max(latencies) / 1_000_000, 3)
    jitter = round (max_latency - min_latency, 3)
    
    # Calculation of average Jitter
    jitters = [] 
    for i in range(1, len(latencies)):
        jitter_value = abs(latencies[i] - latencies[i - 1])
        jitters.append(jitter_value)
    
    tmp_jitter = sum(jitters) / len(jitters) if jitters else 0
    avg_jitter = round(tmp_jitter / 1_000_000, 3)

    return avg_latency, min_latency, max_latency, jitter, avg_jitter

def main():
    pygame.init()
    screen = pygame.display.set_mode((1800, 1000))
    pygame.display.set_caption("WiFi-Circle Test")
    clock = pygame.time.Clock()
    
    circle_window_width = 950
    circle_window_height = 420
    circle_window = pygame.Surface((circle_window_width, circle_window_height))
    
    circle_window.fill((90, 90, 90))

    diagramm_window_width = 1800
    diagramm_window_height = 580
    diagramm_window = pygame.Surface((diagramm_window_width, diagramm_window_height))

    diagramm_window.fill((140, 140, 140))

    legende_window_width = 250
    legende_window_height = 330
    legende_window = pygame.Surface((legende_window_width, legende_window_height))
 
    legende_window.fill((110,110,110))


    points = read_points("circle_points")
    latencies = read_latencies("latencys") 
    
    avg_latency, min_latency, max_latency, jitter, avg_jitter = calculate_latency_statistics(latencies)
    
    print(f"Durchschnittliche Latenz: {avg_latency:.2f} ms")
    print(f"Kleinste Latenz: {min_latency} ms")
    print(f"Größte Latenz: {max_latency} ms")
    print(f"Größter Jitter: {jitter} ms")
    print(f"Durchschnittlicher Jitter: {avg_jitter:.2f} ms")
    
    # Zählen der Latenzen über 3 ms
    over_3ms_count = sum(1 for latency in latencies if latency / 1_000_000 > 3)
    print(f"Latenzen über 3 ms: {over_3ms_count}")

    latency_count = len(latencies)

    # Start Pygame window
    running = True
    while running:
        screen.fill((120, 120, 120)) 
        screen.blit(circle_window, (850, 0))
        screen.blit(diagramm_window, (0, 420))
        screen.blit(legende_window, (20, 620))

        # Draw points
        for point in points:
            pygame.draw.circle(screen, (0, 255, 0), point, 3)
        
        # Draw latency diagramm
        bar_width = 1
        for i, latency in enumerate(latencies):
            bar_height = (latency / 1_000_000) / max_latency *  bar_scale
            three_ms_normed = 3 / max_latency * bar_scale
            pygame.draw.rect(screen, (0, 0, 0), (x_offset + i * (bar_width + 1), 950 - bar_height, bar_width, bar_height))

        avg_latency_pos = avg_latency / max_latency * bar_scale
        avg_jitter_pos = avg_jitter / max_latency * bar_scale
       
        pygame.draw.line(screen, (0, 255, 255), (x_offset, 950 - avg_latency_pos), (1750, 950 - avg_latency_pos), 4)  # Durchschnittliche Latenz (blau)
        
        pygame.draw.line(screen, (255, 255, 0), (x_offset, 950 - avg_jitter_pos), (1750, 950 - avg_jitter_pos), 4)  # Jitter (gelb)

        pygame.draw.line(screen, (255, 0, 0), (x_offset, 950 - three_ms_normed), (1750, 950 - three_ms_normed), 4)

        # Anzeige der Latenzstatistiken
        font = pygame.font.SysFont("Arial", 23)
        title = pygame.font.SysFont("Arial", 25)
        title.set_bold(True)
        title.set_underline(True)


        label = title.render("Data of the Test", True, (255, 255, 255))
        screen.blit(label, (30, 25))


        label = font.render(f"Count of transmitted packages: {latency_count}", True, (255, 255, 255))
        screen.blit(label, (30, 75))

        label = font.render(f"Count of real time violations: {over_3ms_count}", True, (255, 255, 255))
        screen.blit(label, (30, 100))


        label = font.render(f"Average Latency: {avg_latency} ms", True, (255, 255, 255))
        screen.blit(label, (30, 150))

        label = font.render(f"Minimal Latency: {min_latency} ms", True, (255, 255, 255))
        screen.blit(label, (30, 175))

        label = font.render(f"Maximum Latency: {max_latency} ms", True, (255, 255, 255))
        screen.blit(label, (30, 200))

        
        label = font.render(f"Average Jitter: {avg_jitter} ms", True, (255, 255, 255))
        screen.blit(label, (30, 250))

        label = font.render(f"Maximum Jitter: {jitter} ms", True, (255, 255, 255))
        screen.blit(label, (30, 275))


        label = font.render("-- Average Latency", True, (0, 255, 255))
        screen.blit(label, (30, 950 - 80))
       
        label = font.render("-- Average Jitter", True, (255, 255, 0))
        screen.blit(label, (30, 950 - 130))
        
        label = font.render("-- 3ms barrier", True, (255, 0, 0))
        screen.blit(label, (30, 950 - 180))

        label = font.render("-- Latency", True, (0, 0, 0))
        screen.blit(label, (30, 950 - 230))

        label = title.render("Legende", True, (255, 255, 255))
        screen.blit(label, (30, 950 - 300))


        label = title.render("Visualisation of the circle", True, (255, 255, 255))
        screen.blit(label, (900, 50))

        label = title.render("Visualisation of the Test-Data", True, (255, 255, 255))
        screen.blit(label, (700, 450))



        pygame.display.flip()  # Anzeige aktualisieren
        clock.tick(60)  # 60 FPS limit
        
        # Beenden der Anwendung
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
    
    pygame.quit()
    sys.exit()

if __name__ == "__main__":
    main()
