from search import search_urls

keywords = ["huascar", "Adidas", "Sebastian"]

for keyword in keywords:
    print(f"\nBuscando URLs para: {keyword}")
    urls = search_urls(keyword)
    for i, url in enumerate(urls, start=1):
        print(f"{i}. {url}")
