# Protocolo Seguro
Este protocolo consiste em três ou mais entidades.

### Entidades
Para esta parte de autenticação, vamos usar 3 entidades: 
- Alice
- Bob
- Gateway

## Autenticação
Alice e o Bob vão gerar as suas próprias chaves.
Gateway vai servir como uma CA (Certificate Authority), quando uma entidade conecta-se ao Gateway simultaneamente vai ser mandado um CSR para o Gateway. O Gateway vai gerar um certificado para essa mesma entidade. 

![image](https://github.com/user-attachments/assets/0710338b-0ec2-4638-b929-f3cc8afaedf5)
