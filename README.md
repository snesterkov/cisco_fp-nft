## cisco_fp-nft

Преобразование конфигурации Csico FirePower (NGFW Version 6.4.0.7 ) в формат nftables.  
Скрипту передается конфигурационный файл Cisco (show running-config) и список access-list для переноса.  
На выходе получаем список команд для загрузки в цепочку DOCKER-USER  
`nft add rule ip filter DOCKER-USER`