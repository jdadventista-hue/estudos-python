#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Laboratório 1: Análise de Baixo Nível com Sockets TCP
Objetivo: Medir latência do Handshake e inspecionar códigos de retorno do kernel.
"""

import socket
import time

def testar_porta(alvo: str, porta: int, timeout: float = 2.0) -> None:
    """Mede a latência e o código de retorno da tentativa de conexão TCP."""
    
    # 1. Criação do socket IPv4 (AF_INET) e protocolo TCP (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Define o tempo limite máximo de espera
        s.settimeout(timeout)
        
        # Marca o tempo inicial de alta precisão
        inicio = time.perf_counter()
        
        # Executa a tentativa de Handshake (retorna código numérico)
        codigo = s.connect_ex((alvo, porta))
        
        # Marca o tempo final
        fim = time.perf_counter()
        
        # Calcula o tempo total em milissegundos
        duracao_ms = (fim - inicio) * 1000

        # Diagnóstico amigável baseado no código do kernel
        status = "ABERTA (SYN-ACK recebido)" if codigo == 0 else f"NÃO ABERTA (Erro {codigo})"

        print(f"Porta {porta:<5} | Código: {codigo:<5} | Tempo: {duracao_ms:6.2f} ms | Status: {status}")

def main():
    alvo = "scanme.nmap.org"
    print(f"[*] Iniciando análise de baixo nível contra: {alvo}")
    print("-" * 65)
    
    # Teste 1: Porta sabidamente aberta (Servidor Web)
    testar_porta(alvo, 80)
    
    # Teste 2: Porta provavelmente fechada/filtrada
    testar_porta(alvo, 9999)
    
    print("-" * 65)

if __name__ == "__main__":
    main()