package cnvd

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/gocolly/colly"
	"github.com/gocolly/colly/extensions"
)

const (
	baseURL = "https://www.cnvd.org.cn/flaw/list.htm"
)

var (
	rxCNVD = regexp.MustCompile(`(?i)CNVD-\d{4}-\d+`)
	space  = regexp.MustCompile(`\s+`)
)

type Vuln struct {
	URL         string `json:"url"`
	Title       string `json:"title"`
	ID          string `json:"cnvd_id"`
	Date        string `json:"publishedDate"`
	Hazard      string `json:"hazard"`
	Product     string `json:"product"`
	Description string `json:"description"`
	Types       string `json:"types"`
	Reference   string `json:"reference"`
	Attachment  string `json:"attachment"`
}

func CrawlCNVD() ([]Vuln, error) {
	items := make([]Vuln, 0)

	cookies, err := getCookies()
	log.Printf("setting cookies: %s", cookies)
	if err != nil {
	    return nil, fmt.Errorf("error setting cookies: %v", err)
	}

	c := colly.NewCollector(
		colly.AllowedDomains("www.cnvd.org.cn"),
	)
	c.SetRequestTimeout(15 * time.Second)
	err = c.Limit(&colly.LimitRule{
		DomainGlob:  "*cnvd.*",
		Parallelism: 2,
		RandomDelay: 5 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	// extensions.RandomUserAgent(c)

	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("Connection", "keep-alive")
		// r.Headers.Set("Cache-Control", "max-age=0")
		// r.Headers.Set("Upgrade-Insecure-Requests", "1")
		r.Headers.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/87.0.4280.88 Safari/537.36")
		// r.Headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
		// r.Headers.Set("Origin", "https://www.cnvd.org.cn/")
		// r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
		// r.Headers.Set("Sec-Fetch-Site", "none")
		// r.Headers.Set("Sec-Fetch-Mode", "navigate")
		// r.Headers.Set("Sec-Fetch-User", "?!")
		// r.Headers.Set("Sec-Fetch-Dest", "document")
		// r.Headers.Set("Referer", "https://www.cnvd.org.cn/")
		r.Headers.Set("Cookie", cookies)
		log.Printf("visiting %s", r.URL.String())
	})
	c.OnError(func(r *colly.Response, err error) {
		log.Printf("Request URL: %s\nFailed with response: %d %s\nError: %+v\n", r.Request.URL, r.StatusCode, r.Body, err)
	})

	detailCollector := c.Clone()
	extensions.RandomUserAgent(detailCollector)

	c.OnHTML("body > div.mw.Main.clearfix > div.blkContainer > div > div:nth-child(2) > table > tbody > tr.current", func(e *colly.HTMLElement) {
		var link, title, hazard, publishedDate string
		e.ForEach("td", func(i int, el *colly.HTMLElement) {
			switch i {
			case 0:
				link = el.ChildAttr("a", "href")
				title = el.ChildText("a")
			case 1:
				hazard = parseCNHazard(el.Text)
			case 5:
				publishedDate = strings.TrimSpace(el.Text)
			}

		})
		detailURL := e.Request.AbsoluteURL(link)
		id := extractCNVDID(detailURL)
		if link == "" || title == "" || publishedDate == "" || id == "" || detailURL == "" {
			log.Printf("missing CNVD detail in table row on page: %s\n", e.Request.URL)
			return
		}
		err = detailCollector.Visit(detailURL)
		if err != nil {
			// grab title date, parse CNVD ID and pass into item with null values for details
			cnvdItem := Vuln{
				Title:  title,
				URL:    detailURL,
				ID:     id,
				Hazard: hazard,
				Date:   publishedDate,
			}
			items = append(items, cnvdItem)
			log.Printf("detailCollector failed request for %s, grabbing top level only", id)
		}
	})

	detailCollector.OnHTML("body > div.mw.Main.clearfix > div.blkContainer > div.blkContainerPblk > div.blkContainerSblk ", func(e *colly.HTMLElement) {
		cnvdItem := Vuln{
			Title: e.ChildText("h1"),
			URL:   e.Request.URL.String(),
		}

		e.ForEach("div.blkContainerSblkCon.clearfix > div.tableDiv > table > tbody > tr", func(_ int, el *colly.HTMLElement) {
			switch el.ChildText("td:first-child") {
			case "CNVD-ID":
				cnvdItem.ID = el.ChildText("td:nth-child(2)")
			case "公开日期":
				cnvdItem.Date = el.ChildText("td:nth-child(2)")
			case "危害级别":
				cnvdItem.Hazard = parseCNHazard(el.ChildText("td:nth-child(2)"))
			case "影响产品":
				cnvdItem.Product = space.ReplaceAllString(el.ChildText("td:nth-child(2)"), " ")
			case "漏洞描述":
				cnvdItem.Description = space.ReplaceAllString(el.ChildText("td:nth-child(2)"), " ")
			case "漏洞类型":
				cnvdItem.Types = el.ChildText("td:nth-child(2)")
			case "参考链接":
				cnvdItem.Reference = el.ChildText("td:nth-child(2)")
			case "漏洞附件":
				attachment := el.ChildText("td:nth-child(2)")
				if strings.Contains(attachment, "附件暂不公开") {
					attachment = ""
				}
				cnvdItem.Attachment = attachment
			}
		})
		items = append(items, cnvdItem)
		log.Printf("successful detail scrape for %s", cnvdItem.ID)
	})

	// This is to get links in a loop, because CNVD needs post data to get the next page
	// for i := 0; i < 128800; i += 100 {
	for i := 0; i < 100; i += 100 {
		postData := make(map[string]string)
		postData["max"] = "100"
		postData["offset"] = strconv.Itoa(i)
		// Using the POST method, tested the cnvd front end to use the post method to display the next page
		err = nextBaseRequest(c, postData)
		if err != nil {
			return nil, err
		}
	}

	return items, nil
}

func getCookies() (string, error) {
	var cookies string

	options := []chromedp.ExecAllocatorOption{
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.Flag("ignore-certificate-errors", "1"),
	}
	// if env has GOOGLE_CHROME_SHIM
	chromeBin, exists := os.LookupEnv("GOOGLE_CHROME_SHIM"); if exists {
	    options = append(options, chromedp.ExecPath(chromeBin))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second * 20)
	defer cancel()
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, options...)
	defer cancel()
	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// chromedp.ListenTarget(ctx, func(event interface{}) {
	// 	switch responseReceivedEvent := event.(type) {
	// 	case *network.EventResponseReceived:
	// 		response := responseReceivedEvent.Response
	// 		fmt.Printf("Request: %s\n", response.RequestHeadersText)
	// 		fmt.Printf("Response: %d %+v\n", response.Status, response.Headers)
	// 	}
	// })

	err := chromedp.Run(taskCtx, chromedp.Tasks{
		// bypass selenium webdriver detection
		chromedp.ActionFunc(func(cxt context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument("Object.defineProperty(navigator, 'webdriver', { get: () => false, });").Do(cxt)
			if err != nil {
				return err
			}
			return nil
		}),
		// navigate to site
		chromedp.Navigate("https://www.cnvd.org.cn/flaw/list.htm"),
		// read network values
		chromedp.Sleep(time.Second * 5),

		chromedp.ActionFunc(func(ctx context.Context) error {
			ck, err := network.GetAllCookies().Do(ctx)
			if err != nil {
				return err
			}

			cookieSep := "; "
			lastIdx := len(ck) - 1
			for i, c := range ck {
				if i == lastIdx {
					cookieSep = ""
				}
				cookies += fmt.Sprintf("%s=%s%s", c.Name, c.Value, cookieSep)
			}

			return nil
		}),
	})

	if err != nil {
		return "", err
	}

	if !strings.Contains(cookies, "__jsluid_s") || !strings.Contains(cookies, "__jsl_clearance_s") {
		return "", fmt.Errorf("required cookie values not set: %s", cookies)
	}

	return cookies, nil
}

func nextBaseRequest(c *colly.Collector, postData map[string]string) error {
	err := c.Post(fmt.Sprintf("%s?flag=true", baseURL), postData)
	if err != nil {
		return fmt.Errorf("error requesting POST loop: %v\n", err)
	}
	return nil
}

func parseCNHazard(cn string) (en string) {
	if strings.Contains(cn, "中") {
		en = "medium"
		return
	} else if strings.Contains(cn, "高") {
		en = "high"
		return
	} else if strings.Contains(cn, "低") {
		en = "low"
		return
	}
	return
}

func extractCNVDID(r string) string {
	res := rxCNVD.FindAllString(r, -1)
	return strings.ToUpper(res[0])
}
