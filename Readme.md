### Scope
AWS EC2, AI, Grafana, Cloudwatch

### Infra	
- AWS EC2, AI, Grafana, Cloudwatch, Langchain

### Objective

- For comprehensive service analysis, if we get service alarm in Slack channel, AI get that alarm through polling slack channel and then
It analyze that information based on Monitoring tool such like Grafana, Cloudwatch, Cloudwatch logs etc.



### Goals & Non-Goals
#### Goals
- automate analysis course using AI and response immediately as soon as alarm events
- provide comprehensive analysis based on facts of events and monitoring tools, not bias opinion according to personal thought 
Basic architecture




Test result
environment
input channel (slack) : input-event
output channel (slack) : out-event
input event (example)


output event that analyzed events (example)


