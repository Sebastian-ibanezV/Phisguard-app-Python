from whois_lookup import get_domain_info

urls = [
    "https://www.nike.com/",
    "https://www.adidas.com/",
    "https://www.apple.com/",
    "https://sitiowebfalso123.com/"  # dominio inventado para ver el error
]

for url in urls:
    print(f"\nAnalizando: {url}")
    info = get_domain_info(url)
    for k, v in info.items():
        print(f"{k}: {v}")
