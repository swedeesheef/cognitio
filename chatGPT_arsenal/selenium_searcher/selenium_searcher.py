from selenium import webdriver
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import time

def google_dork_search(target_url, search_string):
    driver_path = ChromeDriverManager(path="~/.cache/selenium").install()

    options = webdriver.ChromeOptions()
    options.add_argument("--headless")  # Run in headless mode
    driver = webdriver.Chrome(executable_path=driver_path, options=options)
    try:
        # Your search logic
        query = f'site:{target_url} "{search_string}"'
        google_search_url = f'https://www.google.com/search?q={query}'
        
        driver.get(google_search_url)
        time.sleep(2)

        search_results = driver.find_elements(By.CSS_SELECTOR, 'div.g')
        results = []
        for result in search_results:
            try:
                title = result.find_element(By.TAG_NAME, 'h3').text
                link = result.find_element(By.TAG_NAME, 'a').get_attribute('href')
                snippet = result.find_element(By.CSS_SELECTOR, 'span.aCOpRe').text
                results.append({'title': title, 'link': link, 'snippet': snippet})
            except Exception as e:
                continue
        
        return results

    finally:
        driver.quit()

# Prompt user for input
if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., example.com): ")
    search_string = input("Enter the search string: ")

    results = google_dork_search(target_url, search_string)
    print("\nSearch Results:")
    for result in results:
        print(f"Title: {result['title']}")
        print(f"Link: {result['link']}")
        print(f"Snippet: {result['snippet']}\n")

