import pagehtml from 'errorpages.template.js'
import definitions from 'errorpages.definitions.js'

function guessLang (request) {
    var acceptLanguage = (request.headersIn['Accept-Language'] || '').split(',')
        .map((elm) => elm.trim().slice(0, 2).toLowerCase())

    var isUk = acceptLanguage.indexOf('uk')
    var isRu = acceptLanguage.indexOf('ru')
    var lang = 'en'

    if (isUk !== -1 || isRu !== -1) {
        if (isUk !== -1 && isRu !== -1) {
            lang = isUk < isRu ? 'uk' : 'ru'
        } else {
            lang = isUk === -1 ? 'ru' : 'uk'
        }
    }

    return lang
}

function response (request) {
    var status = request.uri.split('/').pop()
    var html = ''

    if (Object.keys(definitions).includes(status)) {
        var lang = guessLang(request)

        html = pagehtml(lang, status, definitions[status][lang])
    }

    request.return(200, html)
}

function badRequest (request) {
    var lang = guessLang(request)

    return pagehtml(lang, '400', definitions['400'][lang])
}

export default { response, badRequest }
