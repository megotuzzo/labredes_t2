<div align="center"> 
  
### 🌐 Monitor de Tráfego de Rede em Tempo Real

Este é um projeto focado no desenvolvimento de uma ferramenta para monitoramento de tráfego de rede em tempo real. O objetivo é capturar, interpretar e classificar pacotes de rede através da manipulação de *raw sockets*. A aplicação fornece uma interface em modo texto para visualizar contadores estatísticos do tráfego. Simultaneamente, a ferramenta escreve um histórico detalhado dos pacotes interceptados em arquivos de log.

*Nota: A arquitetura baseada no mascaramento via "Traffic Tunnel" sugerida originalmente no escopo foi descartada desta implementação por não estar funcionando.*

</div>

### 🕹️ Como Executar

Consulte o arquivo `executar.txt` incluído no repositório para as instruções exatas de compilação e execução. 

Como o programa opera interceptando o tráfego de rede em baixo nível, lembre-se de que ele necessita de privilégios de administrador (`sudo`) para ser executado e capturar os pacotes corretamente.

### 🚀 Tecnologias Utilizadas

O projeto foi desenvolvido focando no estudo aprofundado do funcionamento dos protocolos de rede e do relacionamento entre as diferentes camadas da pilha TCP/IP, utilizando uma arquitetura híbrida:

  * **Java:** Linguagem principal utilizada para a estruturação lógica, parsing e interpretação dos pacotes de rede, além da renderização da interface CLI.
  * **C:** Utilizado de forma auxiliar para a criação do socket em baixo nível, permitindo a captura nativa dos pacotes na interface de rede driblando a pilha do SO.
  * **Raw Sockets:** Para interceptação e cópia de pacotes diretamente na interface física ou virtual.
  * **Manipulação de Arquivos (CSV):** Para a exportação contínua de dados estatísticos e armazenamento persistente dos logs de tráfego.

### 🛠️ Funcionalidades do Código
<pre>
Integração C/Java: O script em C (raw_socket) captura os pacotes brutos do sistema operacional e a aplicação em Java realiza a leitura contínua através do RawPacketReader.
Interface em Modo Texto: A classe Monitor.java centraliza a execução e a exibição dos contadores atualizados para cada tipo de pacote recebido (IP, TCP, UDP, ICMP, DHCP, etc.).
Parsing Avançado: O PacketParser.java inspeciona os bytes e extrai as métricas de cabeçalho necessárias.
Logs Segregados por Camada: A classe CsvLogger.java estrutura e divide o histórico nas seguintes saídas:
  - camada_internet.csv: IPv4, IPv6 e ICMP (IPs de origem/destino, identificadores e tamanho).
  - camada_transporte.csv: TCP e UDP (portas de origem e destino).
  - camada_aplicacao.csv: HTTP, DHCP, DNS e NTP.
</pre>

### 📂 Estrutura de Arquivos
 <pre>
 Monitor.java: Ponto de entrada do programa em Java e controlador da interface de texto.
 PacketParser.java: Lógica dedicada a interpretar os arrays de bytes e extrair dados dos protocolos.
 RawPacketReader.java: Classe responsável por captar o fluxo de dados brutos provenientes da rede.
 CsvLogger.java: Gerenciador exclusivo da gravação em tempo real dos logs em formato CSV.
 raw_socket.c: Código-fonte em linguagem C que implementa a abertura do raw socket.
 raw_socket: Executável pré-compilado do capturador em C.
 camada_*.csv: Arquivos de log de saída gerados dinamicamente pela aplicação.
 executar.txt: Documento com as instruções de compilação e deploy.
 </pre>  

 ## Linguagens Utilizadas:
<div style="display: inline_block"><br>

| Java | C |
| :---: | :---: |
| <img loading="lazy" src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/java/java-original.svg" width="40" height="40"/> | <img loading="lazy" src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/c/c-original.svg" width="40" height="40"/> |

# Autoras:

| [<img loading="lazy" src="https://avatars.githubusercontent.com/u/142232479?v=4" width=115><br><sub>Luiza Hackenhaar Naziazeno</sub>](https://github.com/luizahackenhaarnaziazeno)|  [<img loading="lazy" src="https://avatars.githubusercontent.com/u/141246773?v=4" width=115><br><sub>Maria Eduarda Gotuzzo Da Silva</sub>](https://github.com/megotuzzo)| 
| :---: | :---: | 
</div>
