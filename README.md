# Kubernetes WireGuard Operator

### Progress
- [x] Add WGNetwork
  - [x] IP Assigner
  - [x] Manage Server Key
  - [x] WireGuard Server Deployment
  - [x] Manage Service [LoadBalancer,NodePort,ClusterIP]
- [x] Add WGClient
  - [x] Set IP for Client
  - [x] Generate server and client WireGuard configuration files
  - [x] Cretae client WireGuard ConfigMap
  - [x] Update Server Deployment to apply new client
- [x] Remove WGNetwork
  - [x] Delete IP Assigner
  - [x] Delete Server Deployment and ConfigMaps
  - [x] Delete Service
- [x] Remove WGClient
  - [x] Return Client IP
  - [x] Update Server ConfigMap
  - [x] Update Server Deployment
  - [x] Remove client WireGuard ConfigMap
- [ ] Access PodCIDR by clients via WireGuard
  - [ ] Using NAT or ...
- [ ] Update WGClient
- [ ] Update WGNetwork
- [ ] Handle Client and Server Keys
- [ ] Deploy Operator via Helm
