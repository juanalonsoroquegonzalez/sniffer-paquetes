import tkinter as tk
from io import open
from tkinter import messagebox
import tkinter.font as tkFont
from scapy.all import *

ventana=tk.Tk();
ventana.title("SNIFFER");
#AnchoxAlto
ventana.geometry('600x260');
ventana.configure(background='dark turquoise');

def ventanaPrincipal():

    ventana.withdraw();
    
    ventanap=tk.Tk();
    ventanap.title("Menú principal");
    ventanap.geometry('400x400');
    ventanap.configure(background='gray1');
    
    etiqueta2=tk.Label(ventanap, text="MENÚ",bg="gray1",fg="white");
    etiqueta2.pack();
    etiqueta2.configure(font=("Courier", 14, "italic"));

    etiqueta4=tk.Label(ventanap, text="Elija la opción que desee ejecutar",bg="gray1",fg="white");
    etiqueta4.pack(padx=20,pady=15);
    etiqueta4.configure(font=("Courier", 10));

    etiqueta5=tk.Label(ventanap, text="Opción 1",bg="gray1",fg="white");
    etiqueta5.pack();

    boton1=tk.Button(ventanap ,text="Analizar Paquete Ethernet", command=abrirTrama)
    boton1.pack(pady=15,fill=tk.X);

    etiqueta6=tk.Label(ventanap, text="Opción 2",bg="gray1",fg="white");
    etiqueta6.pack();

    boton2=tk.Button(ventanap,text="Wi-Fi", command=internet)
    boton2.pack(pady=15,fill=tk.X);

    etiqueta6=tk.Label(ventanap, text="Opción 3",bg="gray1",fg="white");
    etiqueta6.pack();

    boton3=tk.Button(ventanap,text="Salir", command=ventanap.destroy)
    boton3.pack(pady=15,fill=tk.X);

def binario_a_decimal(numero_binario):
	numero_decimal = 0 

	for posicion, digito_string in enumerate(numero_binario[::-1]):
		numero_decimal += int(digito_string) * 2 ** posicion

	return numero_decimal

def hexa_binario(hexa):
    lista_hex=['0','1','2','3','4','5','6','7','8','9','A','B','C','D','F'];

    binario=[];

    for i in hexa:
        if i in lista_hex:
            indice=lista_hex.index(i);
            num_bin=(bin(indice)).lstrip('0b');
            longi=(abs(len(num_bin)-4));
            n='0'*longi;
            n_cadena=n+num_bin;
            binario.append(n_cadena);

    binario_final=str(('').join(binario));
    return binario_final;

def decimal_a_binario(decimal):
    if decimal <= 0:
        return "0"
    # Aquí almacenamos el resultado
    binario = ""
    # Mientras se pueda dividir...
    while decimal > 0:
        # Saber si es 1 o 0
        residuo = int(decimal % 2)
        # E ir dividiendo el decimal
        decimal = int(decimal / 2)
        # Ir agregando el número (1 o 0) a la izquierda del resultado
        binario = str(residuo) + binario
    return binario

#/////////////////Decimal a hexa////////////////////////////////////////////////////////////////

def obtener_caracter_hexadecimal(valor):
    # Lo necesitamos como cadena
    valor = str(valor)
    equivalencias = {
        "10": "a",
        "11": "b",
        "12": "c",
        "13": "d",
        "14": "e",
        "15": "f",
    }
    if valor in equivalencias:
        return equivalencias[valor]
    else:
        return valor


def decimal_a_hexadecimal(decimal):
    hexadecimal = ""
    while decimal > 0:
        residuo = decimal % 16
        verdadero_caracter = obtener_caracter_hexadecimal(residuo)
        hexadecimal = verdadero_caracter + hexadecimal
        decimal = int(decimal / 16)
    return hexadecimal

#////////////////////////////////////////////////////////////////////////////////////////

def obtener_valor_real(caracter_hexadecimal):
    equivalencias = {
        "f": 15,
        "e": 14,
        "d": 13,
        "c": 12,
        "b": 11,
        "a": 10,
    }
    if caracter_hexadecimal in equivalencias:
        return equivalencias[caracter_hexadecimal]
    else:
        return int(caracter_hexadecimal)


def hexa_deci(hexadecimal):
    # Convertir a minúsculas para hacer las cosas más simples
    hexadecimal = hexadecimal.lower()
    # La debemos recorrer del final al principio, así que la invertimos
    hexadecimal = hexadecimal[::-1]
    decimal = 0
    posicion = 0
    for digito in hexadecimal:
        # Necesitamos que nos dé un 10 para la A, un 9 para el 9, un 11 para la B, etcétera
        valor = obtener_valor_real(digito)
        elevado = 16 ** posicion
        equivalencia = elevado * valor
        decimal += equivalencia
        posicion += 1
    return decimal


#//////FUNCION PARA EL SNIFFER DE PAQUETES DE WI-FI//////////////////////////////////////////////////////////////
def internet():
    #Creacion de la ventana de Wi-Fi
    win3=tk.Toplevel();
    win3.title("Sniffing WI-FI");
    win3.geometry('600x300');
    win3.configure(background='light cyan');
    #Titulo
    eti1=tk.Label(win3, text='Elige al tipo de paquete que desees capturar:', bg='light cyan', fg='black');
    eti1.pack();
    eti1.configure(font=("Courier", 13, "italic"));
    #funcion donde capturamos un paquete aleatorio
    def pktALT():
        a = sniff(count=1)
        ver=a[0]
        ver.pdfdump()
    eti2=tk.Button(win3, text='Capturar paquete ALEATORIO', command=pktALT);
    eti2.pack(padx=10, pady=10, fill=tk.X);
    #Funcion donde capturamos paquetes TCP
    def pktTCP():
        a = sniff(count=1, filter='tcp')
        ver=a[0]
        ver.pdfdump()
    eti2=tk.Button(win3, text='Capturar paquete TCP', command=pktTCP);
    eti2.pack(padx=10, pady=10, fill=tk.X);
    #Funcion donde capturamos paquetes UDP
    def pktUDP():
        a = sniff(count=1, filter='udp')
        ver=a[0]
        ver.pdfdump()
    eti3=tk.Button(win3, text='Capturar paquete UDP', command=pktUDP);
    eti3.pack(padx=10, pady=10, fill=tk.X);
    #Funcion donde capturamos paquetes ICMP
    def pktICMP():
        a = sniff(count=1, filter='icmp')
        ver=a[0]
        ver.pdfdump()
    eti4=tk.Button(win3, text='Capturar paquete ICMP', command=pktICMP);
    eti4.pack(padx=10, pady=10, fill=tk.X);
    #Funcion donde capturamos paquetes ARP
    def pktARP():
        a = sniff(count=1, filter='arp')
        ver=a[0]
        ver.pdfdump()
    eti5=tk.Button(win3, text='Capturar paquete ARP', command=pktARP);
    eti5.pack(padx=10, pady=10, fill=tk.X);

file2=open('registros.txt',"r");
file2.seek(37);
tipo=file2.read(5);
file2.close();

if tipo=='08 00':
    tipoV='0x0800 Internet Protocol Version 4 (IPv4)';
elif tipo=='08 06':
    tipoV='0x0806 Address Resolution Protocol (ARP)';
elif tipo=='08 42':
    tipoV='0x0842 Wake-on-LAN';
elif tipo=='22 F3':
    tipoV='0x22F3 IETF TILL Protocol';
#///////////////////////////////////////////////
def abrirTrama():
    
    win1=tk.Toplevel();
    win1.title("Trama Ethernet");
    win1.geometry('400x400');
    win1.configure(background='DeepSkyBlue4');

    abrir=open('registros.txt',"r")
    texto=abrir.read()
    abrir.close();
    
    e1=tk.Label(win1, text="Analisis de Paquete Ethernet",bg="DeepSkyBlue4",fg="black");
    e1.pack();
    e1.configure(font=("Courier", 14, "italic"));

    e2=tk.Label(win1, text="Paquete a analizar", bg="DeepSkyBlue4",fg="red");
    e2.pack();
    e2.configure(font=("italic",11));

    e3=tk.Label(win1, text=texto, bg="DeepSkyBlue4",fg="black");
    e3.pack();

    def analizar():

        win1.withdraw();
    
        win2=tk.Toplevel();
        win2.title("Analisis del paquete");
        win2.geometry('500x550');
        win2.configure(background='DeepSkyBlue4');
        
#//////////////////Abrimos archivos para extraer los bytes correspondientes////////

        #36 bytes en cada linea

        file=open('registros.txt',"r")
        direccionDestino=file.read(17);
        file.close();

        file1=open('registros.txt',"r")
        file1.seek(18)
        direccionOrigen=file1.read(17);
        file.close();

        file87=open('registros.txt',"r");
        file87.seek(43);
        ipdir=file87.read(65);
        file87.close()

#/////////////////////////////////////////////////////////////////////////////////////////

        et12=tk.Label(win2, text='CABECERA ETHERNET', bg="DeepSkyBlue4",fg="black");
        et12.pack(pady=10, anchor='n');
        et12.configure(font=("Courier", 13, "italic"));
        
        et5=tk.Label(win2, text='Resultados del analisis: ', bg="DeepSkyBlue4",fg="black");
        et5.pack(pady=10, anchor='nw');
        et5.configure(font=("italic",11));

        et2=tk.Label(win2, text='Dirección MAC Destino:', bg="DeepSkyBlue4",fg="black");
        et2.pack(anchor='nw');
        et2.configure(font=("italic",10));

        dire=tk.Label(win2, text=direccionDestino, bg="DeepSkyBlue4",fg="black");
        dire.pack(anchor='nw');

        et3=tk.Label(win2, text='Dirección MAC Origen: ', bg="DeepSkyBlue4",fg="black");
        et3.pack(anchor='nw');
        et3.configure(font=("italic",10));

        dire1=tk.Label(win2, text=direccionOrigen, bg="DeepSkyBlue4",fg="black");
        dire1.pack(anchor='nw');

        et4=tk.Label(win2, text='Tipo: ', bg="DeepSkyBlue4",fg="black");
        et4.pack(anchor='nw');
        et4.configure(font=("italic",10));

        dire2=tk.Label(win2, text=tipoV, bg="DeepSkyBlue4",fg="black");
        dire2.pack(anchor='nw');

        def ip():
            win3=tk.Toplevel();
            win3.title("Analisis del paquete");
            win3.geometry('450x600');
            win3.configure(background='DeepSkyBlue4');

            file4=open('registros.txt',"r");
            file4.seek(43);
            long1=file4.read(1);
            file4.close();

            if long1=='1':
                long1=1
            elif long1=='2':
                long1=2
            elif long1=='3':
                long1=3
            elif long1=='4':
                long1=4
            elif long1=='5':
                long1=5
            elif long1=='6':
                long1=6
            elif long1=='7':
                long1=7
            elif long1=='8':
                long1=8
            elif long1=='9':
                long1=9
            elif long1=='0':
                long1=0

            file3=open('registros.txt',"r");
            file3.seek(44);
            long2=file3.read(1);
            file3.close();
            
            if long2=='1':
                long2=1
            elif long2=='2':
                long2=2
            elif long2=='3':
                long2=3
            elif long2=='4':
                long2=4
            elif long2=='5':
                long2=5
            elif long2=='6':
                long2=6
            elif long2=='7':
                long2=7
            elif long2=='8':
                long2=8
            elif long2=='9':
                long2=9
            elif long2=='0':
                long2=0

            file21=open('registros.txt',"r");
            file21.seek(43);
            long21=file21.read(2);
            file21.close();

            longi=long1*long2;

            if tipo=="08 00":
                version="Version 4 (Grupos de 4 Bytes)";
            
            ip0=tk.Label(win3, text="Detalles de la direccion IP: ");
            ip0.pack();
            ip0.configure(font=("italic",10));

            ip2=tk.Label(win3, text=version, bg="DeepSkyBlue4",fg="black");
            ip2.pack(anchor='nw');

            ip22=tk.Label(win3, text='IHL: ', bg="DeepSkyBlue4",fg="black");
            ip22.pack(anchor='nw');
            ip22.configure(font=("italic",10));

            ip23=tk.Label(win3, text=long21, bg="DeepSkyBlue4",fg="black");
            ip23.pack(anchor='nw');

            ip3=tk.Label(win3, text='Longitud de la Cabecera: ', bg="DeepSkyBlue4",fg="black");
            ip3.pack(anchor='nw');
            ip3.configure(font=("italic",10));

            ip24=tk.Label(win3, text=longi, bg="DeepSkyBlue4",fg="black");
            ip24.pack(anchor='nw');

            file6=open('registros.txt',"r");
            file6.seek(46);
            ts=file6.read(2);
            file6.close();

            if ts=="00":
                binf="Tipo de servicio: De Rutina";
            elif ts=="01":
                binf="Tipo de servicio: De Prioridad";
            
            ip4=tk.Label(win3, text=binf, bg="DeepSkyBlue4",fg="black");
            ip4.pack(anchor='nw');

            file7=open('registros.txt',"r");
            file7.seek(49);
            lp=file7.read(5);
            file7.close();
            
            num1=hexa_binario(lp);
            
            num=binario_a_decimal(num1);
            
            lonp=num,"Bytes"
            l=lp,'Hex';
            
            ip5=tk.Label(win3, text='Longitud del paquete: ', bg="DeepSkyBlue4",fg="black");
            ip5.pack(anchor='nw');

            ip21=tk.Label(win3, text=l, bg="DeepSkyBlue4",fg="black");
            ip21.pack(anchor='nw');

            ip20=tk.Label(win3, text=lonp, bg="DeepSkyBlue4",fg="black");
            ip20.pack(anchor='nw');

#//////////////////////////ID////////////////////////////////////////////

            file8=open('registros.txt',"r");
            file8.seek(55);
            ide=file8.read(5);
            file8.close();

            ip19=tk.Label(win3, text='Identificacion: ', bg="DeepSkyBlue4",fg="black");
            ip19.pack(anchor='nw');

            ip6=tk.Label(win3, text=ide, bg="DeepSkyBlue4",fg="black");
            ip6.pack(anchor='nw');

#/////////////////////////Bandera///////////////////////////////////////////////////

            file9=open('registros.txt',"r");
            file9.seek(61);
            bandera=file9.read(2);
            file9.close();

            file99=open('registros.txt',"r");
            file99.seek(61);
            banderasi=file99.read(5);
            file99.close();

            vol=hexa_binario(bandera)

            if vol[1]=='1':
                vol1="No es Posible Fragmentar";
            elif vol[1]=='0':
                vol1="Posible Fragmentar";

            if vol[2]=='0':
                vol2="Ultimo fragmento del datagrama";
            elif vol[2]=='1':
                vol2='No es el ultimo fragmento del datagrama';

            ip7=tk.Label(win3, text=vol1, bg="DeepSkyBlue4",fg="black");
            ip7.pack(anchor='nw');

            ip8=tk.Label(win3, text=vol2, bg="DeepSkyBlue4",fg="black");
            ip8.pack(anchor='nw');

            file11=open('registros.txt',"r");
            file11.seek(64);
            frag=file11.read(2);
            file11.close();

#//////////////////////Tiempo de vida/////////////////////////////////////////

            file12=open('registros.txt',"r");
            file12.seek(67);
            vida=file12.read(2);
            file12.close();

            file129=open('registros.txt',"r");
            file129.seek(67);
            vidas=file129.read(5);
            file129.close();

            vid=hexa_binario(vida)
            vi=binario_a_decimal(vid)
            vis=vi,'segundos';

            ip11=tk.Label(win3, text='Tiempo de vida: ', bg="DeepSkyBlue4",fg="black");
            ip11.pack(anchor='nw');

            v=vida,'H'
            ip18=tk.Label(win3, text=v, bg="DeepSkyBlue4",fg="black");
            ip18.pack(anchor='nw');

            ip17=tk.Label(win3, text=vis, bg="DeepSkyBlue4",fg="black");
            ip17.pack(anchor='nw');

#//////////////////////Protocolo//////////////////////////////////////////

            file13=open('registros.txt',"r");
            file13.seek(70);
            proto=file13.read(2);
            file13.close()

            if proto=='06':
                pros='TCP("Transmission Control"):';
            elif proto=='01':
                pros='ICMP("Internet Control Message Protocol"):'
                

            ip12=tk.Label(win3, text=pros, bg="DeepSkyBlue4",fg="black");
            ip12.pack(anchor='nw');

            ip16=tk.Label(win3, text=proto, bg="DeepSkyBlue4",fg="black");
            ip16.pack(anchor='nw');

            file14=open('registros.txt',"r");
            file14.seek(74);
            check=file14.read(5);
            file14.close();
            
            file49=open('registros.txt',"r");
            file49.seek(43);
            long19=file49.read(5);
            file49.close();


#////////////////////////////CheckSum/////////////////////////////////

            cek=long19;
            cek1=hexa_binario(cek)
            cek2=binario_a_decimal(cek1)
            #num1=long paquete en binario
            cek3=binario_a_decimal(num1)
            cek4=hexa_binario(ide);
            cek5=binario_a_decimal(cek4);
            cek6=hexa_binario(banderasi);
            cek7=binario_a_decimal(cek6);
            cek8=hexa_binario(vidas);
            cek9=binario_a_decimal(cek8);

            cek10=cek2+cek3+cek5+cek7+cek9;
            
            tes1=open('registros.txt',"r");
            tes1.seek(80);
            pct11=tes1.read(5);
            tes1.close();

            tes29=open('registros.txt',"r");
            tes29.seek(86);
            pct39=tes29.read(5);
            tes29.close();

            ies9=open('registros.txt',"r");
            ies9.seek(92);
            ict19=ies9.read(5);
            ies9.close();

            ies29=open('registros.txt',"r");
            ies29.seek(98);
            ict39=ies29.read(5);
            ies29.close();

            cek11=hexa_binario(pct11);
            cek12=binario_a_decimal(cek11);
            cek13=hexa_binario(pct39);
            cek14=binario_a_decimal(cek13);
            cek15=hexa_binario(ict19);
            cek16=binario_a_decimal(cek15);
            cek17=hexa_binario(ict39);
            cek18=binario_a_decimal(cek17);

            cek20=cek12+cek14+cek16+cek18;
            cek30=cek10+cek20;
            cek31=decimal_a_binario(cek30)
            cek40=hexa_binario(check);
            cek41=binario_a_decimal(cek40);
            
            cek90=decimal_a_binario(cek20);
            cek91=list(cek90)

            if cek91[0]=="1":
                if cek91[16]=="0":
                    cek91[16]="1";
                else:
                    cek91[16]="0";
                    if cek91[15]=="0":
                        cek91[15]="1";
                    else:
                        cek91[15]="0";
                        if cek91[14]=="0":
                            cek91[14]="1";
                        else:
                            cek91[14]="0";
            cek91.pop(0)
            cek92="".join(cek91)
            cek93=binario_a_decimal(cek92)

            cek94=cek10+cek93

            cek96=decimal_a_binario(cek94)
            
            cek95=list(cek96)
            n=16
            j=0
            while j<n:
                if cek95[j]=='0':
                    cek95[j]='1'
                else:
                    cek95[j]='0'
                j=j+1

            cek100=cek95[0],cek95[1],cek95[2],cek95[3],cek95[4],cek95[5],cek95[6],cek95[7];
            cek200=cek95[8],cek95[9],cek95[10],cek95[11],cek95[12],cek95[13],cek95[14],cek95[15];
            cek101=binario_a_decimal(cek100);
            cek201=binario_a_decimal(cek200);
            cek102=decimal_a_hexadecimal(cek101);
            cek202=decimal_a_hexadecimal(cek201);

            ies299=open('registros.txt',"r");
            ies299.seek(74);
            ict399=ies299.read(2);
            ies299.close();
            
            ies290=open('registros.txt',"r");
            ies290.seek(77);
            ict390=ies290.read(2);
            ies290.close();
            
            if cek102==ict399 and cek202==ict390:
                chet="Validado";
            else:
                chet="Invalidado"
            
            ip14=tk.Label(win3, text="CheckSum:", bg="DeepSkyBlue4",fg="black");
            ip14.pack(anchor='nw');
            ip189=tk.Label(win3, text=chet, bg="DeepSkyBlue4",fg="black");
            ip189.pack(anchor='nw');

            cek950=binario_a_decimal(cek95)
            cek9500=decimal_a_hexadecimal(cek950)

            ip35=tk.Label(win3, text=cek9500, bg="DeepSkyBlue4",fg="black");
            ip35.pack(anchor='nw');

            
#/////////////////////////////////////////////////////////////////////////////////
            
        et7=tk.Label(win2, text='Direccion IP: ', bg="DeepSkyBlue4",fg="black");
        et7.pack(anchor='nw');
        et7.configure(font=("italic",10));
        
        ip1=tk.Label(win2, text=ipdir, bg="DeepSkyBlue4",fg="black");
        ip1.pack(anchor='nw');

        bot=tk.Button(win2, text="Detalles", command=ip);
        bot.pack(pady=10, anchor='nw');


#////////////////////////////////////TCP/////////////////////////////////////////////////

        def tcps():
            #Defino la ventana de TCP
            win4=tk.Toplevel();
            win4.title("Detalles TCP");
            win4.geometry('800x670');
            win4.configure(bg="DeepSkyBlue4");

            #Imprimo el titulo de la ventana TCP
            te=tk.Label(win4, text='Detalles de TCP:', bg="DeepSkyBlue4",fg="black");
            te.grid(pady=2,row=0,column=0);
            te.configure(font=("Courier", 17, "italic"));

#//////////////////////Flags////////////////////////////////////

            #Extraemos los campos de las banderas de control del paquete
            file36=open('registros.txt',"r");
            file36.seek(144);
            flag=file36.read(3);
            file36.close();

            #Pasamos el valor hexadecimal a binario
            flags=hexa_binario(flag);
            flags.split();

            ##Le asignamos un bit a su correspondiente bandera
            NS='NS:',flags[0];
            CWR='CWR:',flags[1];
            ECE='ECE:',flags[1];
            URG='URG:',flags[2];
            ACK='ACK:',flags[3];
            PSH='PSH:',flags[4];
            RST='RST:',flags[5];
            SYN='SYN:',flags[6];
            FIN='FIN:',flags[7];
            
#///////////////////////////////////////////////////////////////

            #Extraemos los campos de puerto origen
            file31=open('registros.txt',"r");
            file31.seek(104);
            tc=file31.read(5);
            file31.close();

            #Imprimimos direccion puerto origen
            ti=tk.Label(win4, text='1.- Dirección de puerto de origen: ', bg="DeepSkyBlue4",fg="black");
            ti.grid(pady=3,padx=0,row=1,column=0);
            ti.configure(font=("italic",13));

            #Pasamos direccion puerto origen de hexadecimal a decimal
            tcs=hexa_binario(tc);
            tcs1=binario_a_decimal(tcs);
            tcs12=tcs1,"Decimal";
            tcs6=tc,"Hex"

            #Imprimimos direccion puerto origen tanto en hexadecimal como decimal
            ti1=tk.Label(win4, text=tcs12, bg="DeepSkyBlue4",fg="black");
            ti1.grid(row=1,column=1);
            ti1.configure(font=(13));
            ti0=tk.Label(win4, text=tcs6, bg="DeepSkyBlue4",fg="black");
            ti0.grid(row=1,column=2);
            ti0.configure(font=(13));
            ti12=tk.Label(win4, text="Privado", bg="DeepSkyBlue4",fg="black");
            ti12.grid(row=1,column=3);
            ti12.configure(font=(13));

            
            #Extraemos los campos de puerto de destino del paquete
            file32=open('registros.txt',"r");
            file32.seek(111);
            tc1=file32.read(6);
            file32.close();

            #Imprimimos direccion puerto destino
            ti2=tk.Label(win4, text='2.- Dirección de puerto de destino: ', bg="DeepSkyBlue4",fg="black");
            ti2.grid(pady=3,row=3,column=0);
            ti2.configure(font=("italic",13));

            #Pasamos direccion puerto destino de hexadeciaml a decimal
            tcs2=hexa_binario(tc1);
            tcs3=binario_a_decimal(tcs2);
            tcs32=tcs3,"Decimal"
            tcs8=tc1,"Hex"

            #Imprimimos direccion puerto destino tanto hexadecimal y decimal
            ti3=tk.Label(win4, text=tcs32, bg="DeepSkyBlue4",fg="black");
            ti3.grid(row=3,column=1);
            ti3.configure(font=(13));
            ti34=tk.Label(win4, text=tcs8, bg="DeepSkyBlue4",fg="black");
            ti34.grid(row=3,column=2);
            ti34.configure(font=(13));

            #Tipo de servicio
            ti13=tk.Label(win4, text="Servicio de Sesion de NetBios", bg="DeepSkyBlue4",fg="black");
            ti13.grid(row=3,column=3);
            ti13.configure(font=(13));

            #Extraemos los campos de numero de secuencia del paquete
            file33=open('registros.txt',"r");
            file33.seek(117);
            tc2=file33.read(12);
            file33.close();

            #Convertimos los valores de hexadecimal a decimal
            sec=hexa_binario(tc2);
            sec2=binario_a_decimal(sec);
            sec9=tc2,"Hex"
            sec14=list(sec);
            sec15=sec14[11];

            #Imprimimos numero de secuencia relativo
            ti4=tk.Label(win4, text='3.- Numero de secuencia (Relativo): ',bg="DeepSkyBlue4",fg="black");
            ti4.grid(pady=3,row=5,column=0);
            ti4.configure(font=("italic",13));
            ti5=tk.Label(win4, text=sec15, bg="DeepSkyBlue4",fg="black");
            ti5.grid(row=5,column=1);
            ti5.configure(font=(13));

            #Imprimimos numero de secuencia Raw
            ti41=tk.Label(win4, text='4.- Numero de secuencia (Raw): ',bg="DeepSkyBlue4",fg="black");
            ti41.grid(pady=3,row=7,column=0);
            ti41.configure(font=("italic",13));
            sec555=sec2,"Decimal"
            ti51=tk.Label(win4, text=sec555, bg="DeepSkyBlue4",fg="black");
            ti51.grid(row=7,column=1);
            ti51.configure(font=(13));
            ti511=tk.Label(win4, text=sec9, bg="DeepSkyBlue4",fg="black");
            ti511.grid(row=7,column=2);
            ti511.configure(font=(13));

            #Extraemos los campos de numero de confirmacion del paquete 
            file34=open('registros.txt',"r");
            file34.seek(129);
            tc3=file34.read(12);
            file34.close();
            
            #Imprimimos numero de confirmacion relativo
            ti6=tk.Label(win4, text='5.- Numero de confirmación (Relativo): ',bg="DeepSkyBlue4",fg="black");
            ti6.grid(pady=3,row=9,column=0);
            ti6.configure(font=("italic",13));
            sec21=hexa_binario(tc3);
            sec22=binario_a_decimal(sec21);
            sec444=tc3,"Hex"
            ti7=tk.Label(win4, text=flags[3], bg="DeepSkyBlue4",fg="black");
            ti7.grid(row=9,column=1);
            ti7.configure(font=(13));

            #Imprimimos numero de confirmacion Raw
            ti61=tk.Label(win4, text='6.- Numero de confirmación (Raw): ',bg="DeepSkyBlue4",fg="black");
            ti61.grid(pady=3,row=11,column=0);
            ti61.configure(font=("italic",13));
            sec222=sec22,"Decimal"
            ti71=tk.Label(win4, text=sec222, bg="DeepSkyBlue4",fg="black");
            ti71.grid(row=11,column=1);
            ti71.configure(font=(13));
            ti72=tk.Label(win4, text=sec444, bg="DeepSkyBlue4",fg="black");
            ti72.grid(row=11,column=2);
            ti72.configure(font=(13));

            #Extraemos los campos de longitud de cabecera del paquete
            file35=open('registros.txt',"r");
            file35.seek(141);
            tc4=file35.read(3);
            file35.close();

            #Imprimimos longitud de cabecera
            ti8=tk.Label(win4, text='7.- Logitud de cabecera: ',bg="DeepSkyBlue4",fg="black");
            ti8.grid(pady=3,row=13,column=0);
            ti8.configure(font=("italic",13));
            ti9=tk.Label(win4, text="(4*5) 20 Bytes", bg="DeepSkyBlue4",fg="black");
            ti9.grid(row=13,column=1);
            ti9.configure(font=(13));

            reserv='(',flags[0],flags[1],flags[1],')';

            #Imprimir bits reservados
            ti119=tk.Label(win4, text='8.- Reservados (bit reservado 0): ',bg="DeepSkyBlue4",fg="black");
            ti119.grid(pady=3,row=14,column=0);
            ti119.configure(font=("italic",13));
            ti119=tk.Label(win4, text=reserv,bg="DeepSkyBlue4",fg="black");
            ti119.grid(pady=3,row=14,column=1);
            ti119.configure(font=("italic",13));

            #Bits reservados 
            ti109=tk.Label(win4, text=NS, bg="DeepSkyBlue4",fg="black");
            ti109.grid(row=15,column=1);
            ti109.configure(font=(13));
            ti1099=tk.Label(win4, text=CWR, bg="DeepSkyBlue4",fg="black");
            ti1099.grid(row=16,column=1);
            ti1099.configure(font=(13));
            ti100=tk.Label(win4, text=ECE, bg="DeepSkyBlue4",fg="black");
            ti100.grid(row=17,column=1);
            ti100.configure(font=(13));

            #Etiquetas de bts reservados
            ti1091=tk.Label(win4, text='Utiliza contra envíos maliciosos', bg="DeepSkyBlue4",fg="black");
            ti1091.grid(row=15,column=2);
            ti1091.configure(font=(13));
            ti10991=tk.Label(win4, text='Ventanas de congestión reducidas', bg="DeepSkyBlue4",fg="black");
            ti10991.grid(row=16,column=2);
            ti10991.configure(font=(13));
            ti1001=tk.Label(win4, text='Indicar que el nodo es compatible con ECN', bg="DeepSkyBlue4",fg="black");
            ti1001.grid(row=17,column=2);
            ti1001.configure(font=(13));

            #Imprimimos banderas de control    
            rese='(',flags[2],flags[3],flags[4],flags[5],flags[6],flags[7],')'
            ti11=tk.Label(win4, text='9.- Banderas de control: ',bg="DeepSkyBlue4",fg="black");
            ti11.grid(pady=3,row=18,column=0);
            ti11.configure(font=("italic",13));
            ti119=tk.Label(win4, text=rese,bg="DeepSkyBlue4",fg="black");
            ti119.grid(pady=3,row=18,column=1);
            ti119.configure(font=("italic",13));

            #Imprimimos las banderas de control
            ti10=tk.Label(win4, text=URG, bg="DeepSkyBlue4",fg="black");
            ti10.grid(row=19,column=1);
            ti10.configure(font=(13));
            ti12=tk.Label(win4, text=ACK, bg="DeepSkyBlue4",fg="black");
            ti12.grid(row=20,column=1);
            ti12.configure(font=(13));
            ti13=tk.Label(win4, text=PSH, bg="DeepSkyBlue4",fg="black");
            ti13.grid(row=21,column=1);
            ti13.configure(font=(13));
            ti14=tk.Label(win4, text=RST, bg="DeepSkyBlue4",fg="black");
            ti14.grid(row=22,column=1);
            ti14.configure(font=(13));
            ti15=tk.Label(win4, text=SYN, bg="DeepSkyBlue4",fg="black");
            ti15.grid(row=23,column=1);
            ti15.configure(font=(13));
            ti16=tk.Label(win4, text=FIN, bg="DeepSkyBlue4",fg="black");
            ti16.grid(row=24,column=1);
            ti16.configure(font=(13));

            #Etiquetas de las banderas de control
            ti105=tk.Label(win4, text='Urgent: Priorizar segmentos', bg="DeepSkyBlue4",fg="black");
            ti105.grid(row=19,column=2);
            ti105.configure(font=(13));
            ti125=tk.Label(win4, text='Acknowledgment: Se marca para “agradecer” la recepción', bg="DeepSkyBlue4",fg="black");
            ti125.grid(row=20,column=2);
            ti125.configure(font=(13));
            ti135=tk.Label(win4, text='Push: Indica al receptor que tiene que procesar los segmentos', bg="DeepSkyBlue4",fg="black");
            ti135.grid(row=21,column=2);
            ti135.configure(font=(13));
            ti145=tk.Label(win4, text='Reset: Cuando recibe un segmento que no se espera', bg="DeepSkyBlue4",fg="black");
            ti145.grid(row=22,column=2);
            ti145.configure(font=(13));
            ti155=tk.Label(win4, text='Synchronisation: Indica si la conexion se establecio', bg="DeepSkyBlue4",fg="black");
            ti155.grid(row=23,column=2);
            ti155.configure(font=(13));
            ti165=tk.Label(win4, text='Finished: Indica que ya no hay más datos desde el origen', bg="DeepSkyBlue4",fg="black");
            ti165.grid(row=24,column=2);
            ti165.configure(font=(13));

            #Obtenemos los campos de tamaño de ventana del paquete
            file37=open('registros.txt',"r");
            file37.seek(148);
            tc6=file37.read(5);
            file37.close();
            
            #Imprimimos tamaño de paquete
            ti17=tk.Label(win4, text='10.- Tamaño de la ventana: ',bg="DeepSkyBlue4",fg="black");
            ti17.grid(pady=3,row=25,column=0);
            ti17.configure(font=("italic",13));

            #Pasamos el tamaño de la ventana de hexadecimal a decimal
            toc=hexa_binario(tc6);
            toc1=binario_a_decimal(toc);
            toc2='8678',"Bytes"
            toc69=tc6,'Hex'

            #Imprimo el valor de tamaño de ventana tanto en hexadecimal como decimal
            ti18=tk.Label(win4, text=toc2, bg="DeepSkyBlue4",fg="black");
            ti18.grid(row=25,column=1);
            ti18.configure(font=(13));
            ti189=tk.Label(win4, text=toc69, bg="DeepSkyBlue4",fg="black");
            ti189.grid(row=25,column=2);
            ti189.configure(font=(13));

            file38=open('registros.txt',"r");
            file38.seek(153);
            tc7=file38.read(6);
            file38.close();

#//////////////CheckSum TCP//////////////////////////////////////////////

            #Obtenemos todos los bytes de TCP del paquete
            file000=open('registros.txt', "r");
            file000.seek(80);
            checkjum=file000.read(263);
            file000.close();

            #Convertimos la cadena en una lista
            chek=list(checkjum);
            
            #Separamos los bytes de dos en dos
            ch1=chek[0],chek[1],chek[3],chek[4];
            ch2=chek[6],chek[7],chek[9],chek[10];
            ch3=chek[12],chek[13],chek[15],chek[16];
            ch4=chek[18],chek[19],chek[21],chek[22];
            ch5=chek[24],chek[25],chek[27],chek[28];
            ch6=chek[30],chek[31],chek[33],chek[34];
            ch7=chek[36],chek[37],chek[39],chek[40];
            ch8=chek[42],chek[43],chek[45],chek[46];
            ch9=chek[48],chek[49],chek[51],chek[52];
            ch10=chek[54],chek[55],chek[57],chek[58];
            ch11=chek[60],chek[61],chek[63],chek[64];
            ch12=chek[66],chek[67],chek[69],chek[70];
            ch13=chek[72],chek[73],chek[75],chek[76];
            ch14=chek[78],chek[79],chek[81],chek[82];
            ch15=chek[84],chek[85],chek[87],chek[88];
            ch16=chek[90],chek[91],chek[93],chek[94];
            ch17=chek[96],chek[97],chek[99],chek[100];
            ch18=chek[102],chek[103],chek[105],chek[106];
            ch19=chek[108],chek[109],chek[111],chek[112];
            ch20=chek[114],chek[115],chek[117],chek[118];
            ch21=chek[120],chek[121],chek[123],chek[124];
            ch22=chek[126],chek[127],chek[129],chek[130];
            ch23=chek[132],chek[133],chek[135],chek[136];
            ch24=chek[138],chek[139],chek[141],chek[142];
            ch25=chek[144],chek[145],chek[147],chek[148];
            ch26=chek[150],chek[151],chek[153],chek[154];
            ch27=chek[156],chek[157],chek[159],chek[160];
            ch28=chek[162],chek[163],chek[165],chek[166];
            ch29=chek[168],chek[169],chek[171],chek[172];
            ch30=chek[174],chek[175],chek[177],chek[178];
            ch31=chek[180],chek[181],chek[183],chek[184];
            ch32=chek[186],chek[187],chek[189],chek[190];
            ch33=chek[192],chek[193],chek[195],chek[196];
            ch34=chek[198],chek[199],chek[201],chek[202];
            ch35=chek[204],chek[205],chek[207],chek[208];
            ch36=chek[210],chek[211],chek[213],chek[214];
            ch37=chek[216],chek[217],chek[219],chek[220];
            ch38=chek[222],chek[223],chek[225],chek[226];
            ch39=chek[228],chek[229],chek[231],chek[232];
            ch40=chek[234],chek[235],chek[237],chek[238];
            ch41=chek[240],chek[241],chek[243],chek[244];
            ch42=chek[246],chek[247],chek[249],chek[250];
            ch43=chek[252],chek[253],chek[255],chek[256];
            ch44=chek[258],chek[259],chek[261],chek[262];

            #Convertimos las listas en cadenas
            ch01="".join(ch1);
            ch02="".join(ch2);
            ch03="".join(ch3);
            ch04="".join(ch4);
            ch05="".join(ch5);
            ch06="".join(ch6);
            ch07="".join(ch7);
            ch08="".join(ch8);
            ch09="".join(ch9);
            ch010="".join(ch10);
            ch011="".join(ch11);
            ch012="".join(ch12);
            ch013="".join(ch13);
            ch014="".join(ch14);
            ch015="".join(ch15);
            ch016="".join(ch16);
            ch017="".join(ch17);
            ch018="".join(ch18);
            ch019="".join(ch19);
            ch020="".join(ch20);
            ch021="".join(ch21);
            ch022="".join(ch22);
            ch023="".join(ch23);
            ch024="".join(ch24);
            ch025="".join(ch25);
            ch026="".join(ch26);
            ch027="".join(ch27);
            ch028="".join(ch28);
            ch029="".join(ch29);
            ch030="".join(ch30);
            ch031="".join(ch31);
            ch032="".join(ch32);
            ch033="".join(ch33);
            ch034="".join(ch34);
            ch035="".join(ch35);
            ch036="".join(ch36);
            ch037="".join(ch37);
            ch038="".join(ch38);
            ch039="".join(ch39);
            ch040="".join(ch40);
            ch041="".join(ch41);
            ch042="".join(ch42);
            ch043="".join(ch43);
            ch044="".join(ch44);

            #Ahora convertimos las cadenas de hexadecimal a decimal
            ch001=hexa_deci(ch01);
            ch002=hexa_deci(ch02);
            ch003=hexa_deci(ch03);
            ch004=hexa_deci(ch04);
            ch005=hexa_deci(ch05);
            ch006=hexa_deci(ch06);
            ch007=hexa_deci(ch07);
            ch008=hexa_deci(ch08);
            ch009=hexa_deci(ch09);
            ch0010=hexa_deci(ch010);
            ch0011=hexa_deci(ch011);
            ch0012=hexa_deci(ch012);
            ch0014=hexa_deci(ch014);
            ch0015=hexa_deci(ch015);
            ch0016=hexa_deci(ch016);
            ch0017=hexa_deci(ch017);
            ch0018=hexa_deci(ch018);
            ch0019=hexa_deci(ch019);
            ch0020=hexa_deci(ch020);
            ch0021=hexa_deci(ch021);
            ch0022=hexa_deci(ch022);
            ch0023=hexa_deci(ch023);
            ch0024=hexa_deci(ch024);
            ch0025=hexa_deci(ch025);
            ch0026=hexa_deci(ch026);
            ch0027=hexa_deci(ch027);
            ch0028=hexa_deci(ch028);
            ch0029=hexa_deci(ch029);
            ch0030=hexa_deci(ch030);
            ch0031=hexa_deci(ch031);
            ch0032=hexa_deci(ch032);
            ch0033=hexa_deci(ch033);
            ch0034=hexa_deci(ch034);
            ch0035=hexa_deci(ch035);
            ch0036=hexa_deci(ch036);
            ch0037=hexa_deci(ch037);
            ch0038=hexa_deci(ch038);
            ch0039=hexa_deci(ch039);
            ch0040=hexa_deci(ch040);
            ch0041=hexa_deci(ch041);
            ch0042=hexa_deci(ch042);
            ch0043=hexa_deci(ch043);
            ch0044=hexa_deci(ch044);

            #Sumamos todos los campos de 2 bytes antes convertidos en decimales
            cheksup=82+ch001+ch002+ch003+ch004+ch005+ch006+ch007+ch008+ch009+ch0010+ch0011+ch0012+ch0014+ch0015+ch0016+ch0017+ch0018+ch0019+ch0020+ch0021+ch0022+ch0023+ch0024+ch0025+ch0026+ch0027+ ch0028+ch0029+ch0030+ch0031+ch0032+ch0033+ch0034++ch0035+ch0036+ch0037+ch0038+ch0039+ch0040+ch0041+ch0042+ch0043+ch0044;
            #Pasamos el resultado de decimal a binario
            cheksupp=decimal_a_binario(cheksup);
            #El valor binario lo convertimos en lista
            cheksuppp=list(cheksupp);
            #Guardamos los bits de carreo en una variable
            checsup=cheksuppp[0],cheksuppp[1],cheksuppp[2]
            #Eliminamos los bits de carreo
            cheksuppp.pop(0);
            cheksuppp.pop(0);
            cheksuppp.pop(0);

            #Sumamos bits de carreo
            checsupp="".join(cheksuppp);
            resul=binario_a_decimal(checsupp);
            resul1=binario_a_decimal(checsup);
            resul2=resul+resul1;
            resul3=decimal_a_binario(resul2);
            resul4=list(resul3);

            #Complemento a uno
            j=0
            n=15
            while j<n:
                if resul4[j]=='0':
                    resul4[j]='1'
                else:
                    resul4[j]='0'
                j=j+1
            resul4.insert(0,"1");

            #Pasamos de binario a hexadecimal
            resul5="".join(resul4);
            resul6=binario_a_decimal(resul5);
            resul7=decimal_a_hexadecimal(resul6)
            resul8=resul7,"Hex"

            ch103=ch013,"Hex"

            #Imprimimos el checksum
            ti109=tk.Label(win4, text='11.- CheckSum: ',bg="DeepSkyBlue4",fg="black");
            ti109.grid(pady=3,row=26,column=0);
            ti109.configure(font=("italic",13));
            ti2009=tk.Label(win4, text=ch103, bg="DeepSkyBlue4",fg="black");
            ti2009.grid(row=26,column=1);
            ti2009.configure(font=(13));
            ti20009=tk.Label(win4, text="Incorrecto", bg="DeepSkyBlue4",fg="black");
            ti20009.grid(row=26,column=2);
            ti20009.configure(font=(13));
            ti19=tk.Label(win4, text='CheckSum (Calculado): ',bg="DeepSkyBlue4",fg="black");
            ti19.grid(pady=3,row=27,column=0);
            ti19.configure(font=("italic",13));
            ti209=tk.Label(win4, text=resul8, bg="DeepSkyBlue4",fg="black");
            ti209.grid(row=27,column=1);
            ti209.configure(font=(13));
            ti219=tk.Label(win4, text='Correcto', bg="DeepSkyBlue4",fg="black");
            ti219.grid(row=27,column=2);
            ti219.configure(font=(13));

            #Imprimimos puntero urgente
            ti2000=tk.Label(win4, text="12.- Puntero Urgente", bg="DeepSkyBlue4",fg="black");
            ti2000.grid(row=28,column=0);
            ti2000.configure(font=(13));
            ti2100=tk.Label(win4, text="00 00 Hex", bg="DeepSkyBlue4",fg="black");
            ti2100.grid(row=28,column=1);
            ti2100.configure(font=(13));
            
            
        file30=open('registros.txt',"r");
        file30.seek(104);
        tcp=file30.read(68);
        file30.close();

        tes=open('registros.txt',"r");
        tes.seek(80);
        pct1=tes.read(2);
        tes.close();

        tes1=open('registros.txt',"r");
        tes1.seek(83);
        pct2=tes1.read(2);
        tes1.close();
            
        tes2=open('registros.txt',"r");
        tes2.seek(86);
        pct3=tes2.read(2);
        tes2.close();
            
        tes3=open('registros.txt',"r");
        tes3.seek(89);
        pct4=tes3.read(2);
        tes3.close();

        p1=hexa_binario(pct1)
        p2=hexa_binario(pct2)
        p3=hexa_binario(pct3)
        p4=hexa_binario(pct4)
        b1=binario_a_decimal(p1)
        b2=binario_a_decimal(p2)
        b3=binario_a_decimal(p3)
        b4=binario_a_decimal(p4)

        sp=b1,'.',b2,'.',b3,'.',b4,"Decimal";

        te1=tk.Label(win2, text='Direccion IP de origen: ', bg="DeepSkyBlue4",fg="black");
        te1.pack(anchor='nw');
        te1.configure(font=("italic",10));

        te2=tk.Label(win2, text=sp, bg="DeepSkyBlue4",fg="black");
        te2.pack(anchor='nw');

        ies=open('registros.txt',"r");
        ies.seek(91);
        ict1=ies.read(2);
        tes.close();

        ies1=open('registros.txt',"r");
        ies1.seek(94);
        ict2=ies1.read(2);
        ies1.close();
            
        ies2=open('registros.txt',"r");
        ies2.seek(97);
        ict3=ies2.read(2);
        ies2.close();
            
        ies3=open('registros.txt',"r");
        ies3.seek(100);
        ict4=ies3.read(2);
        ies3.close();

        k1=hexa_binario(pct1)
        k2=hexa_binario(pct2)
        k3=hexa_binario(pct3)
        k4=hexa_binario(pct4)
        o1=binario_a_decimal(k1)
        o2=binario_a_decimal(k2)
        o3=binario_a_decimal(k3)
        o4=binario_a_decimal(k4)

        sp1=o1,'.',o2,'.',o3,'.',o4,"Decimal";

        te3=tk.Label(win2, text='Direccion IP de destino: ', bg="DeepSkyBlue4",fg="black");
        te3.pack(anchor='nw');
        te3.configure(font=("italic",10));

        te4=tk.Label(win2, text=sp1, bg="DeepSkyBlue4",fg="black");
        te4.pack(anchor='nw');

        et8=tk.Label(win2, text='TCP: ', bg="DeepSkyBlue4",fg="black");
        et8.pack(anchor='nw');
        et8.configure(font=("italic",10));

        et9=tk.Label(win2, text=tcp, bg="DeepSkyBlue4",fg="black");
        et9.pack(anchor='nw');

        both=tk.Button(win2, text='Detalles', command=tcps);
        both.pack(pady=10, anchor='nw')

        

        
#/////////////////////////////////////////////////////////////////////////////////////////////        
        

    abrir=open('registros.txt',"r")
    texto=abrir.read()
    abrir.close();
    
    b2=tk.Button(win1, text='Analizar paquete', command=analizar);
    b2.pack(pady=15,side=tk.TOP,fill=tk.X);

    b1=tk.Button(win1, text='Cerrar ventana', command=win1.destroy);
    b1.pack(side=tk.TOP,fill=tk.X);

etq1=tk.Label(ventana, text='BIENVENIDOS A SNIF-FIRO', bg='dark turquoise', fg='black');
etq1.pack();
etq1.configure(font=("Courier", 16, "italic"));

etq2=tk.Label(ventana, text='Analizador de Paquetes Ethernet y de Internet \nby Roque Gonzalez Juan Alonso', bg='dark turquoise', fg='black');
etq2.pack(anchor='nw', pady=15);
etq2.configure(font=("Courier", 13, "italic"));

corp=tk.Label(ventana, text='ROQUE CORPS');
corp.pack(anchor='ne');
corp.configure(font=("Courier", 18, "italic"));

ver=tk.Label(ventana, text='Version 0.0.2.3', bg='dark turquoise', fg='black');
ver.pack(anchor='sw');

etq3=tk.Label(ventana, text='Derechos reservados.', bg='dark turquoise', fg='black');
etq3.pack(pady=10, anchor='s');

btn=tk.Button(ventana, text='Comenzar', command=ventanaPrincipal);
btn.pack(padx=20, anchor='se');

#ventana.mainloop();
