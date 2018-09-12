# DDos_attack_defense

  TCP協定中，client欲與server溝通，需先透過3-way handshake建立連線。
DDoS TCP SYN攻擊（Distributed Denial-of-Service TCP SYN attack）是一種網路攻擊方法，
利用TCP必須經過3-way handshake才能建立連線的特性，client向特定目標發送SYN封包，
server收到SYN封包並回應後，會等待client的ACK封包以建立連線，若client刻意不送出ACK封包，
則server會持續等待ACK封包直到逾時。這些半開通連線會占用server的資源，若同一時間有大量的半開通連線，
可能導致server的資源都被半開通連線占用，使server的服務暫時中斷或停止，導致正常用戶無法存取其所需的資源。

  SDN網路架構利用OpenFlow協定將路由器的控制層（Control Plane）與資料層（Data Plane）分離，
網路交由Controller以軟體方式控制，使得網路管理更具彈性。此專題研究計畫在SDN架構下，
使用Open vSwitch與Ryu controller實作，為達到防禦SYN攻擊的需求，須在Open vSwitch新增
TCP SEQ field、TCP ACK field與這兩個field的set field action，並修改Ryu原始碼，使其支援這兩個field。
	
預設情況下，client會直接與server作3-way handshake，controller會定期檢查送給server的封包數量，
若數量超過某個值，則會啟動防禦系統，由switch作為server前的防線，client須作2次3-way handshake
才能與server建立連線，第一次，client先與switch做3-way handshake，若client正確傳回ack封包，
才能直接與server進行handshake，此做法可阻擋大量的DDoS攻擊封包同時進入server，
讓server可以正常服務有需求的client。
