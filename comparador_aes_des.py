from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time
import sys
# ------------------------------------------------------------
# PASSO 0: INSTALAR BIBLIOTECAS NECESSÁRIAS
# ------------------------------------------------------------
# Descomente a linha abaixo se estiver executando em um notebook
# !pip install pycryptodome matplotlib

# ------------------------------------------------------------
# TRABALHO DE CRIPTOGRAFIA SIMÉTRICA - TEMA 1
# Comparador de Desempenho AES vs DES
# ------------------------------------------------------------
# Este código foi adaptado para cumprir os requisitos do Tema 1:
# 1. Cifra arquivos de 1KB, 1MB e 10MB
# 2. Mede o tempo de processamento (média de 10 execuções) #[cite: 14, 21]
# 3. Calcula o throughput (MB/s)
# 4. Gera relatório em tabela
# 5. Plota gráficos com matplotlib
# 6. Usa AES/DES em modo CBC  com padding PKCS7 #[cite: 20] e IV aleatório
# ------------------------------------------------------------


class CipherComparator:
    def __init__(self):
        # Geração de chaves para cada algoritmo
        self.aes_key_128 = get_random_bytes(16)   # AES-128 (16 bytes)
        self.aes_key_256 = get_random_bytes(32)   # AES-256 (32 bytes)
        # O trabalho pede DES, mas incluímos 3DES para uma comparação mais rica
        self.tdes_key_3k = get_random_bytes(24)   # 3DES com 3 chaves (168 bits)
        self.des_key = get_random_bytes(8)        # DES (56 bits)

    def cipher_aes(self, data, key_size=128, mode=AES.MODE_CBC):
        """Executa cifragem com AES (Modo CBC por padrão)"""
        key = self.aes_key_128 if key_size == 128 else self.aes_key_256

        # Gera IV aleatório para cada operação
        iv = get_random_bytes(16)
        cipher = AES.new(key, mode, iv)
        # Usa padding PKCS7
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return encrypted, iv

    def cipher_3des(self, data, key_type='3k', mode=DES3.MODE_CBC):
        """Executa cifragem com Triple DES (Modo CBC por padrão)"""
        key = self.tdes_key_3k

        iv = get_random_bytes(8)
        cipher = DES3.new(key, mode, iv)
        encrypted = cipher.encrypt(pad(data, DES3.block_size))
        return encrypted, iv

    def cipher_des(self, data, mode=DES.MODE_CBC):
        """Executa cifragem com DES (Modo CBC por padrão) """
        iv = get_random_bytes(8)
        cipher = DES.new(self.des_key, mode, iv)
        encrypted = cipher.encrypt(pad(data, DES.block_size))
        return encrypted, iv

    def benchmark_algorithms(self, data, file_size_mb, iterations=10):
        """Executa testes de desempenho dos algoritmos"""
        print(f"Iniciando benchmark para {file_size_mb:.4f} MB (Média de {iterations} execuções)...") #[cite: 21]
        print("=" * 60)

        results = []
        # Test cases filtrados para os modos CBC, conforme requisito
        test_cases = [
            ("AES-128 CBC", self.cipher_aes, {"key_size": 128, "mode": AES.MODE_CBC}),
            ("AES-256 CBC", self.cipher_aes, {"key_size": 256, "mode": AES.MODE_CBC}),
            ("3DES 3K CBC", self.cipher_3des, {"key_type": "3k", "mode": DES3.MODE_CBC}),
            ("DES CBC", self.cipher_des, {"mode": DES.MODE_CBC}),
        ]

        for name, cipher_func, params in test_cases:
            # print(f"Testando {name}...") # Removido para N ser muito verboso

            # --- Medição do tempo de cifragem ---
            start_time = time.perf_counter()
            for i in range(iterations):
                encrypted, iv = cipher_func(data, **params)
            encrypt_time = (time.perf_counter() - start_time) / iterations # Tempo médio

            # --- Medição do tempo de decifragem ---
            start_time = time.perf_counter()
            for i in range(iterations):
                # Modos com IV (CBC)
                if name.startswith("AES"):
                    key = self.aes_key_128 if "128" in name else self.aes_key_256
                    cipher = AES.new(key, params["mode"], iv)
                    block_size = AES.block_size
                elif name.startswith("3DES"):
                    key = self.tdes_key_3k
                    cipher = DES3.new(key, params["mode"], iv)
                    block_size = DES3.block_size
                else:  # DES
                    cipher = DES.new(self.des_key, params["mode"], iv)
                    block_size = DES.block_size

                decrypted = unpad(cipher.decrypt(encrypted), block_size)

            decrypt_time = (time.perf_counter() - start_time) / iterations # Tempo médio

            # Verificação de integridade
            integrity_ok = (decrypted == data)

            # Cálculo de Throughput (MB/s)
            throughput_encrypt_mb_s = file_size_mb / encrypt_time
            throughput_decrypt_mb_s = file_size_mb / decrypt_time

            results.append({
                "algorithm": name,
                "encrypt_time": encrypt_time,
                "decrypt_time": decrypt_time,
                "throughput_encrypt_mb_s": throughput_encrypt_mb_s,
                "throughput_decrypt_mb_s": throughput_decrypt_mb_s,
                "encrypted_size": len(encrypted),
                "integrity_ok": integrity_ok,
                "security_bits": self._get_security_bits(name)
            })

        return results

    def _get_security_bits(self, algorithm_name):
        """Retorna os bits de segurança de cada algoritmo"""
        security_bits = {
            "AES-128 CBC": 128,
            "AES-256 CBC": 256,
            "3DES 3K CBC": 168, # Efetivamente 112 bits, mas 168 é o tamanho da chave
            "DES CBC": 56
        }
        return security_bits.get(algorithm_name, "N/A")

    def print_comparison_table(self, results):
        """Imprime uma tabela comparativa dos resultados """
        print("\n" + "=" * 110)
        print("TABELA COMPARATIVA - AES vs 3DES vs DES")
        print("=" * 110)
        print(f"{'ALGORITMO':<15} {'SEGURANÇA':<10} {'CIFRAR (ms)':<12} {'DECIFRAR (ms)':<14} {'THROUGHPUT CIFRAR (MB/s)':<28} {'THROUGHPUT DECIFRAR (MB/s)':<30} {'INTEGRIDADE':<12}")
        print("-" * 110)

        for result in results:
            encrypt_ms = result["encrypt_time"] * 1000
            decrypt_ms = result["decrypt_time"] * 1000

            print(f"{result['algorithm']:<15} {result['security_bits']:<10} "
                  f"{encrypt_ms:<12.4f} {decrypt_ms:<14.4f} "
                  f"{result['throughput_encrypt_mb_s']:<28.2f} "
                  f"{result['throughput_decrypt_mb_s']:<30.2f} "
                  f"{'OK' if result['integrity_ok'] else 'ERRO':<12}")
        print("\n")

def create_test_files():
    """Gera os arquivos de teste (1KB, 1MB, 10MB) com dados aleatórios """
    print("Criando arquivos de teste (1KB, 1MB, 10MB)...")
    file_specs = {
        "1KB.bin": 1024,
        "1MB.bin": 1024 * 1024,
        "10MB.bin": 10 * 1024 * 1024
    }
    for filename, size in file_specs.items():
        if not os.path.exists(filename):
            print(f"Gerando {filename} ({size} bytes)...")
            with open(filename, 'wb') as f:
                f.write(get_random_bytes(size))
        else:
            print(f"{filename} já existe.")
    print("Arquivos de teste prontos.\n")
    return file_specs.keys()

def plot_comparison_graphs(all_results):
    """Plota gráficos de desempenho usando matplotlib """
    print("Gerando gráficos de desempenho...")

    file_sizes = list(all_results.keys())
    algorithms = [res['algorithm'] for res in all_results[file_sizes[0]]]

    encrypt_throughputs = {alg: [] for alg in algorithms}
    decrypt_throughputs = {alg: [] for alg in algorithms}

    # Extrai dados para os gráficos
    for size in file_sizes:
        results = all_results[size]
        for res in results:
            alg = res['algorithm']
            encrypt_throughputs[alg].append(res['throughput_encrypt_mb_s'])
            decrypt_throughputs[alg].append(res['throughput_decrypt_mb_s'])

    x = np.arange(len(file_sizes)) # Posições das barras
    width = 0.20 # Largura das barras

    # --- Gráfico 1: Throughput de Cifração ---
    fig1, ax1 = plt.subplots(figsize=(12, 7))

    # Cria uma barra para cada algoritmo
    rects1 = ax1.bar(x - 1.5*width, encrypt_throughputs['AES-128 CBC'], width, label='AES-128 CBC')
    rects2 = ax1.bar(x - 0.5*width, encrypt_throughputs['AES-256 CBC'], width, label='AES-256 CBC')
    rects3 = ax1.bar(x + 0.5*width, encrypt_throughputs['3DES 3K CBC'], width, label='3DES 3K CBC')
    rects4 = ax1.bar(x + 1.5*width, encrypt_throughputs['DES CBC'], width, label='DES CBC')

    ax1.set_ylabel('Throughput (MB/s)')
    ax1.set_title('Desempenho de Cifração por Tamanho de Arquivo')
    ax1.set_xticks(x)
    ax1.set_xticklabels(file_sizes)
    ax1.legend()
    ax1.bar_label(rects1, padding=3, fmt='%.1f')
    ax1.bar_label(rects2, padding=3, fmt='%.1f')
    ax1.bar_label(rects3, padding=3, fmt='%.1f')
    ax1.bar_label(rects4, padding=3, fmt='%.1f')

    fig1.tight_layout()
    plt.savefig("grafico_cifracao.png")
    print("Gráfico 'grafico_cifracao.png' salvo.")

    # --- Gráfico 2: Throughput de Decifração ---
    fig2, ax2 = plt.subplots(figsize=(12, 7))

    rects1 = ax2.bar(x - 1.5*width, decrypt_throughputs['AES-128 CBC'], width, label='AES-128 CBC')
    rects2 = ax2.bar(x - 0.5*width, decrypt_throughputs['AES-256 CBC'], width, label='AES-256 CBC')
    rects3 = ax2.bar(x + 0.5*width, decrypt_throughputs['3DES 3K CBC'], width, label='3DES 3K CBC')
    rects4 = ax2.bar(x + 1.5*width, decrypt_throughputs['DES CBC'], width, label='DES CBC')

    ax2.set_ylabel('Throughput (MB/s)')
    ax2.set_title('Desempenho de Decifração por Tamanho de Arquivo')
    ax2.set_xticks(x)
    ax2.set_xticklabels(file_sizes)
    ax2.legend()
    ax2.bar_label(rects1, padding=3, fmt='%.1f')
    ax2.bar_label(rects2, padding=3, fmt='%.1f')
    ax2.bar_label(rects3, padding=3, fmt='%.1f')
    ax2.bar_label(rects4, padding=3, fmt='%.1f')

    fig2.tight_layout()
    plt.savefig("grafico_decifracao.png")
    print("Gráfico 'grafico_decifracao.png' salvo.")

    plt.show()


def main():
    """Função principal para executar o comparador"""
    print("EXERCÍCIO: COMPARADOR DE DESEMPENHO AES vs DES (TEMA 1)")
    print("=" * 60)

    # 1. Gerar arquivos de teste
    file_paths = create_test_files()

    comparator = CipherComparator()
    all_results = {}

    # Define os arquivos e seus tamanhos em MB para o cálculo de throughput
    file_specs = [
        ("1KB.bin", 1024 / (1024 * 1024)),        # 1KB
        ("1MB.bin", (1024*1024) / (1024 * 1024)), # 1MB
        ("10MB.bin", (10*1024*1024) / (1024 * 1024)) # 10MB
    ]

    # 2. Executar benchmarks para cada arquivo
    for filename, size_mb in file_specs:
        print(f"\n{'#' * 70}")
        print(f"TESTE COM ARQUIVO: {filename} (Tamanho: {size_mb * 1024:.0f} KB)")
        print(f"{'#' * 70}")

        # Lê os dados do arquivo
        with open(filename, 'rb') as f:
            test_data = f.read()

        # Executa o benchmark com 10 iterações
        results = comparator.benchmark_algorithms(test_data, size_mb, iterations=10)

        # 3. Imprime a tabela de resultados
        comparator.print_comparison_table(results)

        # Armazena resultados para plotagem
        all_results[filename] = results

    # 4. Plotar gráficos de desempenho
    plot_comparison_graphs(all_results)

    print("\nBenchmark concluído.")

if __name__ == "__main__":
    main()