# Estudos sobre CYBERSECURITY.

Todo conteúdo é com base no curso CYBERSECURITY da fiap.


## Definições.

Cybersecurity abrange um conjunto de normas, procedimento e boas práticas, que ajudam na identificação e mitigação de riscos relacionados a exposições na internet.  


## Vetores de ataque.

Vetor é o motivação ou o meio em qual ocorreu o ataque, os principais são listados a seguir.

## Principais Incidentes Reportados.


- PHISHING: email ou informação falsa compartilhada por meio digital. Maneira de atrair o alvo.

- WORM: atividades maliciosas relacionadas com processo automatizado da propagação de códigos maliciosos na rede.

- BRUTE FORCE: teste de varias possiveis senhas para acesso as credenciais do usuario.

- Dos: Denial of Service, onde o atacante utiliza um computador ou um conjunto de computadores para tirar de operação um serviço, computador ou rede.

- Invasão: Um ataque por acesso não autorizado a um computador ou rede.

- WEB: Ataque que compromete servidores web ou desconfigura páginas web.

- SCAN: analise da rede, por varredura de portas para identificar potenciais alvos.

- FRAUDE: qualquer ato de má fé com o objetivo de lesar ou ludibriar alguem. Enganar.


## Processos Internos.

Todo o levantamento de ativos da empresa para mapeamento de informações é muito importante. Impactando diretamente em processos internos específicos e simples da empresa, como quem tem acesso a informação, a necessidade daquele acesso para tal, o privilegio de acesso do usuario e a politica de segurança que a empresa propaga para evitar ou até mitigar riscos, tratando não apenas os efeitos mas as causas que levaram ao ataque.

## Segurança da Informação.

Definir a segurança da informação em uma só coisa é complicado, digamos que não se resume somente a equipamentos tecnologicos mas tambem processos, pessoas, ferramentas e documentos que regem toda uma area de mercado vasta.

> A segurança da informação pode ser definida como a proteção da informação contra diferentes tipos de ameaças, com o objetivo de garantir a continuidade do negócio, minimizar os riscos aos quais este possa vir a ser exposto. (ISO/IEC 27002:2005)

> A referida proteção da informação pode ser inicialmente entendida como a preservação da confidencialidade, integridade e disponibilidade da informação, essas propriedades complementadas a autenticidade, responsabilidade, não repúdio e confiabilidade, tornam completos todos os pilares da segurança da informação. (ISO/IEC 27001:2005)


**If you think technology can solve your security problems, then you don't understand the problems and you don't understand the technology.**

Não se investe em segurança da informação calculando o retorno (ROI- Return Over Investment), mas sim em quanto se consegue economizar, minimizando os riscos aos quais os ativos da organização possam vir a ser expostos, sem obter benefícios, então dá-se ao negocio o calculo de quanto o investimento pode evitar a perda de dinheiro.

## CID (confidencialidade, integridade e disponibilidade).

Três pilares básicos da Segurança da Informação.

- Confidencialidade: significa que esta acessível unicamente aos que tem autorização para isso.

- Integridade: garante exatidão e plenitude da informação, oque ão garante alterações ao longo do ciclo de vida da informação mas sim as que sejam legítimas.

- Disponibilidade: deve estar acessível a informação quando necessária, aos que tiverem autorização para isso.


## Privilégios minimos (Least Privilege)

A segurança da informação envolve muitos processos, entre os citados a **manutenção de privilégios mínimos** é o enfoque deste capitulo, que é a garantia de que um usuario comum não tenha privilégios semelhantes ao de um administrador.


## Defesa em profundidade (Defense in depth)

A defesa em profundidade é a implementação de um sistema defensivo em forma de camadas, onde varios mecanismos se complementam promovendo o sistema como um todo. 


## Principio da simplicidade (KISS - Keep it Sample, Stupid)

Um principio de que não se deve complitar a situação, que seja sucinto e simples. 

É necessario sempre partir de um script, o ponto inicial para configurações de firewalls ou redes. 

## Segregações de funções. (Separation of duties - SoD)

Método clássico para resolução de conflitos com o foco de previnir fraudes, sempre fazendo com que mais uma pessoa seja necessária para conclusão de uma tarefa. 

> "Implementar uma separação de papéis e responsabilidades que reduza a possibilidade de um único individuo 

## Riscos, vulnerabilidades e ameaças à segurança da informação e á continuidade de negócio. 

### Risco.

O termo RISCO é definido como qualquer evento que possa ter impacto (negativo) sobre a capacidade do serviço.

### Ameaças.

>Ameaças são definidas como a causa potencial de um incidente indesejado, que pode resultar em dano para um sistema ou para a organização.ISO/IEC13335-1:2004

### Vulnerabilidades

É definida uma vulnerabilidade como uma fraqueza em um sistema, deixando suscetíveis a incontáveis atividades que poderão causar perdas ou danos. 

## CVE (Common Vulnerability and Exposures).

Site especializado que padroniza as vulnerabilidades, fornecendo metricas, descrições e informações sobre vulnerabilidades ou exposições de informações de softwares por meio de um numero. 


```html
https://cve.mitre.org/
```
## Ataques e vetores de ataque.

Lembrando que um vetor de ataque é um caminho ou meio utilizado por um ser malicioso para obter acesso não autorizado, como um sistema ou dispositivo. 

- Ataques via browser; (20%) Violaçã por meio de navegador. 
- Ataques por força bruta; (20%) Teste de tentativa e erro.
- Ataques de negação de serviço; (15%) Ataques de sobrecarga de serviço.
- Ataques por worms; (13%) código malicioso que se auto-propaga. 
- Ataques por malwares; (10%) Código malicioso criado para prejudicar, sequestrar ou espionar. 
- Ataques web; (4%) SQL Injection, ataque direcionado a serviços web.
- Varreduras (scan attacks); (4%) Analise de portas abertas. hosts 
- Insiders. (14%) ataques realizado por um objetivo,planejamento e normalmente bem orquestrados. 

#### IDS (Sistema de identificação de intrusos)

## Controles para mitigação de riscos cibernéticos. 

CIS - Center Internet Security (Centro de estudos sobre segurança da internet), onde há um guia de adequação de controles de mitigação de riscos. Com 20 implementações sugestivas.

```html
https://www.cisecurity.org/
```

As principais implementações sugeridas pela CIS são:

- Inventário de dispositivos autorizados e não autorizados.
- Inventário de softwares autorizados e não autorizados.
- Implementação e gerenciamento da configuração segura dos ativos.
- Processos para avaliação e remediação continuada de vulnerabilidades. 
- Uso apropriado de privilégios administrativos.

Uma boa ferramenta para **inventário** é a **OCS inventory**, disponivel em:

```html
https://ocsinventory-ng.org/?lang=en 
```
> Desde 2001, o OCS Inventory procura tornar o inventário de hardware e software de computadores mais eficiente. O OCS Inventory consulta seus agentes para conhecer a composição soft e hard de cada máquina, de cada servidor.

Tambem se torna importante adquirir um SCAP (Security Content Automation Protocol), com maior dificuldade de aplicação, se torna vantajoso para auxiliar no planejamento e execução de varreduras de vulnerabilidades de forma automatizada e periodica. 






