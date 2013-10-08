require 'packetfu'
$incidentNum = 0 #Counter of which incident we are on

def sniff(iface)
    stream = PacketFu::Capture.new(:start => true, 
                                   :iface => iface, 
                                   :promisc => true)

    stream.stream.each do |p|
        pkt = PacketFu::Packet.parse p
        if pkt.proto.include?('TCP')
            checkAttacks(pkt)
        end 
    end
end

def checkAttacks(pkt)
    checkNetScans(pkt)
    checkLeakedPass(pkt)
    if whichProto(pkt.tcp_sport, pkt.tcp_dport) == "HTTP"    
        checkCreditCards(pkt)
        checkXSS(pkt)
    end
end

def checkLeakedPass(pkt)
    passes = ["PASS", "password=", "Password:", "LOGIN Ok."] 
    payload = pkt.payload     
    pass = false
    passes.each do |p|
        pbinary = p.each_byte.map { |b| sprintf(" 0x%02X ",b) }.join
        if payload.include?(p) ||
           payload.include?(pbinary)
            pass = true
        end
    end
    if pass == true
        soundAlarm("Password leaked in the clear", pkt.ip_saddr, 
                                                   pkt.tcp_sport,
                                                   pkt.tcp_dport)
    end
end

def checkCreditCards(pkt)
    payload = pkt.payload
    #note: Regex for credit cards from SANS.org at
    #http://www.sans.org/security-resources/idfaq/snort-detect-credit-card-numbers.php
    if payload =~ /4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ ||
       payload =~ /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ ||
       payload =~ /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ ||
       payload =~ /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/
                   
        soundAlarm("Credit card leaked in the clear", pkt.ip_saddr, 
                                                          pkt.tcp_sport,
                                                         pkt.tcp_dport)
    end     
end

def checkXSS(pkt)
    payload = pkt.payload
    if payload =~ /<script>(.+)?<\/script>/ ||
       payload =~ /%3Cscript%3E(.+)?%3C%2Fscript%3E/         
        soundAlarm("Cross-site scripting attack", pkt.ip_saddr, 
                                                  pkt.tcp_sport,
                                                  pkt.tcp_dport)
    end     
end

def checkNetScans(pkt)
    on_flags = 0
    pkt.tcp_flags.each do |f|
    #count all the zero flags
        if f == 1
           on_flags += 1
        end
    end
    if (on_flags == 0)
        #NULL Scan - all flags on the packet are off
        soundAlarm("NULL scan is detected", pkt.ip_saddr, pkt.tcp_sport,
                                                          pkt.tcp_dport)
    end
    if on_flags == 3
        #Xmas Scan - FIN, PSH, URG
        if (pkt.tcp_flags.fin == 1 &&
            pkt.tcp_flags.psh == 1 &&
            pkt.tcp_flags.urg == 1)
            soundAlarm("Xmas scan is detected", pkt.ip_saddr, pkt.tcp_sport, 
                                                              pkt.tcp_dport)
        end
    end
    if pkt.payload =~ /Nmap/
        soundAlarm("Nmap scan is detected", pkt.ip_saddr, pkt.tcp_sport, 
                                                          pkt.tcp_dport)
    end
end

def soundAlarm(attack, ip, sport, dport)
    proto = whichProto(sport, dport)
    $incidentNum += 1
    puts "%s. ALERT: %s from %s (%s)!" % [$incidentNum, attack, ip, proto]
end

def whichProto(sport, dport)
    #Returns name of protocol used if known, else "TCP"
    if dport == 20
        return "FTP"
    elsif dport == 21
        return "FTP"
    elsif dport == 22
        return "SSH"
    elsif sport == 23
        return "Telnet"
    elsif dport == 25
        return "SMTP"
    elsif dport == 80
        return "HTTP"
    elsif dport == 110
        return "POP"
    elsif sport == 143
        return "IMAP"
    else
        return "TCP"
    end
end

sniff('en1')
