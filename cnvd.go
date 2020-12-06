package cnvd

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

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

	c := colly.NewCollector(
		colly.AllowedDomains("www.cnvd.org.cn"),
	)
	c.SetRequestTimeout(10 * time.Second)
	err := c.Limit(&colly.LimitRule{
		DomainGlob:  "*cnvd.*",
		Parallelism: 2,
		RandomDelay: 5 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	extensions.RandomUserAgent(c)

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
			fmt.Printf("detailCollector failed request for %s, grabbing top level only", id)
		}
	})

	c.OnRequest(func(r *colly.Request) {
		log.Printf("indexCollector visiting %s\n", r.URL.String())
	})

	detailCollector.OnRequest(func(r *colly.Request) {
		log.Printf("detailCollector visiting %s", r.URL.String())
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
		err := c.Post(fmt.Sprintf("%s?flag=true", baseURL), postData)
		if err != nil {
			log.Printf("error requesting POST loop: %v\n", err)
		}
	}

	return items, nil
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
