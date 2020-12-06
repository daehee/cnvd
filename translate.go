package cnvd

import (
    "github.com/mind1949/googletrans"
    "golang.org/x/text/language"
)

func CNToEN(src string) (dst string, err error) {
    params := googletrans.TranslateParams{
        Src:  "auto",
        Dest: language.English.String(),
        Text: src,
    }
    translated, err := googletrans.Translate(params)
    if err != nil {
        return "", err
    }
    dst = translated.Text
    return
}
