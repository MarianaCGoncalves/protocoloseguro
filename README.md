# Protocolo Seguro
Proposto pelo docente de Segurança em Redes e Sistemas de Informação. 

### Entidades
Para simular este protocolo vamos usar 4 entidades: 
- Alice
- Bob
- Charlie
- Gateway

# Comandos necessários 
Execute estes comandos em terminais diferentes:

    python gateway.py
<p>
  Quando arrancamos a alice ou o bob, pede-nos o nome do cliente, se usarmos um nome diferente irá criar uma chave e um certificado novos. 
<p>
    
    python alice.py
<p>
<p>
    
    python bob.py
    
## Autenticação
Quando os clientes entram no gateway, automaticamente geram as suas chaves, e o gateway gera certificado para cada entidade. Antes da sua comunicação cada entidade valida o certificado com quem vai comunicar.
Neste caso observamos a validação entre o Bob e a Alice:
![image](https://github.com/user-attachments/assets/c66d6b4b-8663-4ffa-a14f-dc166be1469e)

### Diagrama da Autenticação
![image](https://github.com/user-attachments/assets/0710338b-0ec2-4638-b929-f3cc8afaedf5)

## Comunicação Segura entre clientes
Com a validação concluída, ambos os clientes podem prosseguir com a sua conversa segura, cada mensagem é encriptada com AES-256 CBC, aqui vai uma imagem explicativa de como procede esta conversa:
![image](https://github.com/user-attachments/assets/011ae50a-216c-470a-9768-a25b35af4c5b)


