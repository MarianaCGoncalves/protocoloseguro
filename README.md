# Protocolo Seguro
Este protocolo consiste em três ou mais entidades.

### Entidades
Para esta parte de autenticação, vamos usar 5 entidades: 
- Alice
- Bob
- Charlie
- Daniel
- Gateway

## Autenticação
Alice, Bob, Charlie e Daniel vão gerar as suas próprias chaves.
Gateway vai servir como uma CA (Certificate Authority), quando uma entidade conecta-se ao Gateway simultaneamente vai ser mandado um CSR para o Gateway. O Gateway vai gerar um certificado para essa mesma entidade. 

![image](https://github.com/user-attachments/assets/0710338b-0ec2-4638-b929-f3cc8afaedf5)

![image](https://github.com/user-attachments/assets/011ae50a-216c-470a-9768-a25b35af4c5b)
Esta imagem é um exemplo da comunicação entre o Bob e a Alice, com os restantes acontecerá algo semelhante

# Comandos necessários 
- phyton alice.py
- phyton bob.py
- phyton charlie.py
- phyton daniel.py
- phyton gateway.py

Estes 5 comandos tem de ser executados em 5 terminais diferentes mas em simultaneo.
Após a execussão do comando irá perguntar o nome da entidade para gerar o par de chaves.

