import socket

import folium 
import requests
from datetime import date

# each hop represents a step in the path that the packet takes to reach its target.
from geopy import Nominatim

import docker
import subprocess, os

# nginx server - initialization: reverse proxy that forwards the current request to tracker services provider
def nginx_init(client):
    # builds docker nginx server image
    try:
        #
        image, build_logs = client.images.build(
            path="./nginx_conf",
            tag="nginx",
            rm=True  # remove intermediate containers after a successful build
        )
        
        # print build logs
        for line in build_logs:
            if 'stream' in line:
                print(line['stream'].strip())

    # print errors (hopefully this section remains unused)
    except docker.errors.BuildError as e:
        print(f"Build failed: {e}")
    except Exception as e:
        print(f"An error occurred during the build: {e}")

    # run the docker image with port mapping
    run_command = ['docker', 'run', '--name', 'nginx_container', '-d', '-p', "8080:80", "nginx"]
    run_output = subprocess.check_output(run_command, stderr=subprocess.STDOUT)

    print("-------------------------------------------------------------------------------------")

# nginx server - stopping the nginx process and erasing the docker image and container, as they are no longer needed
def nginx_destroy(client):
    # getting container from client's containers list - stopping and erasing it
    container = client.containers.get("nginx_container")
    container.stop() 
    container.remove()
    
    # remove the image
    image = client.images.get(container.image.id)
    client.images.remove(image.id)
    
    print(f"Containerul 'nginx_container' si imaginea 'nginx' au fost oprite si indepartate.")

# method that creates the file with the traceroute data coresponding to each chosen domain
def createFile(path_to_folder, name):
    # requesting ipapi without any ip's in order to get the current user's data
    response = requests.get("https://ipapi.co/json/")
    data = response.json()

    # get the ip address and location information
    ip_address = data["ip"]
    city = data["city"]
    # afisare rezultate un fisier + numele_siteului + din ce oras e accesat + la ce ora
    numeFisier = "rezultat_" + name + "_" + city + "_" + str(date.today()) + '_' + ip_address
    w_file = open(path_to_folder + "/" + numeFisier, 'w')

    return w_file

def locate_ip(ip_address):
    # requesting the nginx server, which forwards the request as well to ipinfo server
    api_url = f"http://localhost:8080/{ip_address}/json"
    city, region, country = None, None, None

    # setting up X-Forwarded-For header to bypass error 429
    fake_HTTP_header = {
        'X-Forwarded-For': '1.2.3.4',
    }
    # getting the data
    response = requests.get(api_url, headers=fake_HTTP_header)
    if response.status_code == 200:
        data = response.json()
        print(data)

        city = data.get("city")
        region = data.get("region")
        country = data.get("country")
        
    return city, region, country
   
def traceroute(ip, port, max_hops, udp_send_sock, icmp_recv_socket):
    ip = socket.gethostbyname(ip)
    visited_ips = []

    for ttl in range(1, max_hops + 1):

        # the current TTL value in the IP header for the UDP socket
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # sending a UDP message to the target
        udp_send_sock.sendto(b'hello, I hope it works', (ip, port))

        try:
            data, addr = icmp_recv_socket.recvfrom(63535)  # receive data from the ICMP socket and extract the ICMP type
            icmp_type = data[20]

            # checking the ICMP Type
            if icmp_type == 11:  # Time Exceeded
                visited_ips.append(addr[0])
            elif icmp_type == 3:  # Destination Unreachable
                visited_ips.append(addr[0])
                break  # the destination is reached
            else:
                continue  # the ICMP Type is not relevant, we continue
        except socket.timeout as e:
            print("Socket timeout: ", str(e))
            # print(traceback.format_exc())

    return visited_ips

def createMap(cities, index, name):
    # Set up the map centered on Europe
    geolocator = Nominatim(user_agent="traceroute")
    location = geolocator.geocode("Europe")
    map = folium.Map(location=[location.latitude, location.longitude], zoom_start=4, control_scale=True)

    # Add a custom map style tile layer with attribution
    tile_layer = 'https://cartodb-basemaps-{s}.global.ssl.fastly.net/light_all/{z}/{x}/{y}.png'
    attribution = 'Map data &copy; <a href="https://www.carto.com/">Carto</a>'
    folium.TileLayer(tile_layer, name='Custom Map Style', attr=attribution).add_to(map)

    # Add markers for cities
    for i in range(len(cities)):
        city = cities[i]
        idx = index[i]
        loc = geolocator.geocode(city)
        folium.Marker([loc.latitude, loc.longitude], popup=city, icon=folium.Icon(color='blue', icon='info-sign')).add_to(map)

    # Add connections between cities
    for i in range(len(cities) - 1):
        source_city = cities[i]
        destination_city = cities[i+1]
        source = geolocator.geocode(source_city)
        destination = geolocator.geocode(destination_city)
        folium.PolyLine(locations=[(source.latitude, source.longitude),
                                (destination.latitude, destination.longitude)],
                        color='red',
                        weight=2).add_to(map)

    # Save the map as an HTML file
    map.save("./2_maps/" + "ip_locations_map_" + name + "_" + str(date.today()) + ".html")

def main():
    print("Buna ziua!")
    print("Crearea serverului care se ocupa cu requesturile dvs este in curs...")
    # getting docker current client
    client = docker.from_env()
    # initializing the nginx server
    nginx_init(client)
    
    max_hops = 30

    terminat = False
    while not terminat:
        # UDP socket for sending packets
        udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

        # ICMP raw socket to read ICMP responses
        icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_recv_socket.settimeout(5)

        name = input("Introduceti corect numele domeniului pe care vreti sa il accesati: ")
        path_to_folder = f"./{name}"

        # create the folder containing the traceroute file of the current domain
        if not os.path.isdir(path_to_folder):
            os.makedirs(path_to_folder)

        # create the file containing the traceroute data of the current domain
        w_file = createFile(path_to_folder, name)
        
        # salvam in lista orasele prin care trec pachetele si ordinea lor
        # initializare
        cities = []
        index = []
        nr = 1

        # getting the ips
        ips_list = traceroute(name, 33434, max_hops, udp_send_sock, icmp_recv_socket)

        # getting the locations of the ips, and creating the output file
        for i, ip in enumerate(ips_list, start=1):
            ls_regions = locate_ip(ip)
            if ls_regions[0] is not None:
                # ls = locate_ip(ip)
                cities.append(ls_regions[0])
                index.append(nr)
                nr += 1
                
                print(f'{i}. {ip}  {ls_regions[0]}  {ls_regions[1]}   {ls_regions[2]}')
                w_file.write(f'{i}. {ip}  {ls_regions[0]}  {ls_regions[1]}   {ls_regions[2]}\n')
            else:
                print(f'{i}. {ip}  {"Unknown location"}')
                w_file.write(f'{i}. {ip}  {"Unknown location"}\n')

        # creating the map
        createMap(cities, index, name)

        # closing current socket
        udp_send_sock.close()
        icmp_recv_socket.close()

        terminat = False if input("Doriti sa incercati cu alt domeniu? (y/n) : ") in ["y", "Y"] else True

    # destroying nginx, as it is not needed anymore
    nginx_destroy(client)
    print("Pa pa")

if __name__ == "__main__":
    main()
