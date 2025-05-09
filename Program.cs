using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

class Program
{
    private static readonly string API_KEY_GOOGLE = "";
    private static readonly string API_KEY_VIRUSTOTAL = "";
    private static HashSet<string> blacklistedUrls = new HashSet<string>();

    static async Task Main(string[] args)
    {
        string basePath = AppDomain.CurrentDomain.BaseDirectory;
        string fullCsvPath = Path.Combine(basePath, "localSearch");
        Console.WriteLine($"[DEBUG] localSearch klasörü: {fullCsvPath}");
        LoadLocalCsvFiles(fullCsvPath);

        Console.Write("URL girin: ");
        string inputUrl = Console.ReadLine();

        int riskScore = 0;

        // 1. Yerel CSV kontrolü
        var (csvSus, csvMsg) = CheckAgainstLocalCsv(inputUrl);
        if (csvSus) { riskScore++; PrintWithColor(csvMsg, ConsoleColor.Yellow); }
        else { PrintWithColor(csvMsg, ConsoleColor.Green); }

        // 2. Yerel heuristic kontrol
        var (localSus, localMsg) = LocalUrlCheck(inputUrl);
        if (localSus) { riskScore++; PrintWithColor(localMsg, ConsoleColor.Yellow); }
        else { PrintWithColor(localMsg, ConsoleColor.Green); }

        // 3. Google Safe Browsing kontrolü
        var (googleSus, googleMsg) = await CheckWithGoogleSafeBrowsing(inputUrl);
        if (googleSus) { riskScore++; PrintWithColor(googleMsg, ConsoleColor.Red); }
        else { PrintWithColor(googleMsg, ConsoleColor.Green); }

        // 4. VirusTotal kontrolü
        var (vtSus, vtMsg) = await CheckWithVirusTotal(inputUrl);
        if (vtSus) { riskScore++; PrintWithColor(vtMsg, ConsoleColor.Red); }
        else { PrintWithColor(vtMsg, ConsoleColor.Green); }

        // 5. Sonuç Özeti
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"\n🔗 İncelenen URL: {inputUrl}");
        Console.WriteLine($"📊 Genel Risk Skoru: {riskScore} / 4");

        Console.ForegroundColor = ConsoleColor.White;
    }

    static void LoadLocalCsvFiles(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
        {
            Console.WriteLine($"[HATA] Klasör bulunamadı: {directoryPath}");
            return;
        }

        var csvFiles = Directory.GetFiles(directoryPath, "*.csv");

        foreach (var file in csvFiles)
        {
            Console.WriteLine($"[DEBUG] Yükleniyor: {file}");
            foreach (var line in File.ReadLines(file).Skip(1))
            {
                var parts = line.Split(',');
                if (parts.Length >= 3)
                {
                    var rawUrl = parts[2].Trim('"', ' ', '\t');
                    var normalized = NormalizeUrl(rawUrl);

                    if (normalized.Contains("asdcvbhnbvcxzsdc"))
                        Console.WriteLine($"[DEBUG] CSV'de normalize edilmiş: {normalized}");

                    if (!string.IsNullOrWhiteSpace(normalized))
                        blacklistedUrls.Add(normalized);
                }
            }
        }

        Console.WriteLine($"[✓] Toplam {blacklistedUrls.Count} URL yüklendi.");
    }

    static (bool, string) CheckAgainstLocalCsv(string url)
    {
        string normalizedInput = NormalizeUrl(url);
        Console.WriteLine($"[DEBUG] Normalize edilmiş giriş: {normalizedInput}");

        foreach (var blacklistUrl in blacklistedUrls)
        {
            if (NormalizeUrl(blacklistUrl) == normalizedInput)
            {
                Console.WriteLine($"[MATCH FOUND] → {blacklistUrl}");
                return (true, "Yerel CSV: Şüpheli URL bulundu.");
            }
        }

        return (false, "Yerel CSV: URL temiz.");
    }

    static string NormalizeUrl(string url)
    {
        try
        {
            var uri = new Uri(url.ToLower().Trim());
            return uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        }
        catch
        {
            return url.ToLower().Trim().TrimEnd('/');
        }
    }

    static (bool, string) LocalUrlCheck(string url)
    {
        if (Regex.IsMatch(url, @"http[s]?://\d{1,3}(\.\d{1,3}){3}"))
            return (true, "IP adresi içeriyor.");
        if (url.Split('-').Length > 3)
            return (true, "'-' karakteri fazla.");

        string[] keywords = {
        "login", "update", "verify", "secure", "webscr", "paypal", "banking",
        "signin", "account", "confirm", "submit", "security", "ebay", "amazon",
        "apple", "google", "support", "help", "invoice", "alert", "password",
        "user", "profile", "auth", "authentication", "reset", "recover", "dropbox",
        "drive", "docs", "outlook", "office365", "microsoft", "cloud", "storage",
        "mail", "sms", "phone", "service", "transaction", "wallet", "bitcoin",
        "crypto", "metamask", "coinbase", "binance", "weebly", "webflow", "free",
        "bonus", "promo", "offer", "virus", "download" , "malware.html" // test URL için özel keyword
    };

        foreach (var word in keywords)
            if (url.ToLower().Contains(word)) return (true, $"Şüpheli kelime: {word}");

        if (url.Length > 75)
            return (true, "URL çok uzun.");

        return (false, "Temiz");
    }

    static async Task<(bool, string)> CheckWithGoogleSafeBrowsing(string url)
    {
        var body = new
        {
            client = new { clientId = "csharp-app", clientVersion = "1.0" },
            threatInfo = new
            {
                threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE" },
                platformTypes = new[] { "ANY_PLATFORM" },
                threatEntryTypes = new[] { "URL" },
                threatEntries = new[] { new { url } }
            }
        };

        var jsonBody = JsonConvert.SerializeObject(body);
        using var client = new HttpClient();
        try
        {
            var response = await client.PostAsync(
                $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_GOOGLE}",
                new StringContent(jsonBody, Encoding.UTF8, "application/json")
            );
            var content = await response.Content.ReadAsStringAsync();
            if (content.Contains("matches"))
                return (true, "Google Safe Browsing: Zararlı bulundu.");
            return (false, "Google Safe Browsing: Temiz");
        }
        catch (Exception ex)
        {
            return (true, $"Google API hatası: {ex.Message}");
        }
    }

    static async Task<(bool, string)> CheckWithVirusTotal(string url)
    {
        string encodedUrl = Convert.ToBase64String(Encoding.UTF8.GetBytes(url)).TrimEnd('=');
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Add("x-apikey", API_KEY_VIRUSTOTAL);
        try
        {
            var response = await client.GetAsync($"https://www.virustotal.com/api/v3/urls/{encodedUrl}");
            if (!response.IsSuccessStatusCode)
                return (true, $"VirusTotal API hatası: {response.StatusCode}");

            var content = await response.Content.ReadAsStringAsync();
            dynamic result = JsonConvert.DeserializeObject(content);
            int maliciousCount = result.data.attributes.last_analysis_stats.malicious;
            return maliciousCount > 0
                ? (true, "VirusTotal: Zararlı bulundu.")
                : (false, "VirusTotal: Temiz");
        }
        catch (Exception ex)
        {
            return (true, $"VirusTotal API hatası: {ex.Message}");
        }
    }
    static void PrintWithColor(string message, ConsoleColor color)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(message);
        Console.ForegroundColor = previous;
    }

}
