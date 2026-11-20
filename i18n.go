package main

import (
	"net/http"
	"strings"
)

const langCookie = "kuma-gate-lang"

// translations holds every text the pages show, in pt and en. A key missing in one
// language fails TestTextsInBothLanguages.
var translations = map[string]map[string]string{
	"pt": {
		"title":              "kuma-gate",
		"notes":              "Novidades",
		"notes_lede":         "O que mudou em cada versão.",
		"home":               "Início",
		"open_kuma":          "Abrir o Uptime Kuma",
		"source":             "código",
		"kicker":             "gcn · kuma-gate",
		"part_of":            "parte da",
		"part_of_gcn":        "parte do",
		"logout_a":           "Sair do",
		"logout_b":           "Uptime Kuma",
		"logout_lede":        "Você entrou como %s. Sair encerra a sessão neste navegador.",
		"logout_btn":         "Sair",
		"logout_tabs_local":  "Sair fecha a sessão só neste navegador; uma aba do Kuma já aberta em outro lugar continua até a sessão expirar. Para cortar todas, use “Sair de todos os lugares”.",
		"logout_tabs_remote": "Sair fecha a sessão só neste navegador; uma aba do Kuma já aberta em outro lugar continua até a sessão expirar ou até você sair da lista de acesso.",
		"logout_all_btn":     "Sair de todos os lugares",
		"logout_none":        "Você não está com a sessão aberta neste navegador.",
		"signin":             "Entrar",
		"error_title":        "Algo deu errado",
		"error_400":          "Endereço inválido.",
		"error_401":          "É preciso entrar para ver esta página.",
		"error_403":          "Sem permissão para esta página.",
		"error_403_who":      "Você entrou como %s, mas esta conta não tem acesso ao Uptime Kuma. Saia e entre com outra conta, ou peça acesso a quem administra.",
		"error_404":          "Página não encontrada.",
		"error_405":          "Método não aceito.",
		"error_413":          "O pedido é grande demais.",
		"error_500":          "Erro interno. Tente de novo em instantes.",
		"error_502":          "O Uptime Kuma não respondeu. Tente de novo em instantes.",
		"error_other":        "Não foi possível atender o pedido.",
		"auth_expired":       "O login demorou demais ou foi interrompido. Comece de novo.",
		"auth_denied":        "O login foi recusado no provedor.",
		"auth_upstream":      "O provedor de login não respondeu como esperado. Tente de novo.",
		"auth_role":          "Esta conta não tem um papel que dá acesso.",
		"auth_form":          "O formulário expirou. Recarregue a página e tente de novo.",
		"auth_internal":      "Erro interno no login. Tente de novo.",
	},
	"en": {
		"title":              "kuma-gate",
		"notes":              "Release notes",
		"notes_lede":         "What changed in each version.",
		"home":               "Home",
		"open_kuma":          "Open Uptime Kuma",
		"source":             "source code",
		"kicker":             "gcn · kuma-gate",
		"part_of":            "part of",
		"part_of_gcn":        "part of",
		"logout_a":           "Sign out of",
		"logout_b":           "Uptime Kuma",
		"logout_lede":        "You are signed in as %s. Signing out ends the session in this browser.",
		"logout_btn":         "Sign out",
		"logout_tabs_local":  "Signing out ends the session in this browser only; a Kuma tab already open elsewhere stays until the session expires. To cut them all, use “Sign out everywhere”.",
		"logout_tabs_remote": "Signing out ends the session in this browser only; a Kuma tab already open elsewhere stays until the session expires or you are removed from the access list.",
		"logout_all_btn":     "Sign out everywhere",
		"logout_none":        "You are not signed in in this browser.",
		"signin":             "Sign in",
		"error_title":        "Something went wrong",
		"error_400":          "Invalid address.",
		"error_401":          "You need to sign in to see this page.",
		"error_403":          "You may not open this page.",
		"error_403_who":      "You are signed in as %s, but this account has no access to Uptime Kuma. Sign out and use another account, or ask the administrators for access.",
		"error_404":          "Page not found.",
		"error_405":          "Method not allowed.",
		"error_413":          "The request is too large.",
		"error_500":          "Internal error. Try again in a moment.",
		"error_502":          "Uptime Kuma did not answer. Try again in a moment.",
		"error_other":        "The request could not be served.",
		"auth_expired":       "The sign-in took too long or was interrupted. Start again.",
		"auth_denied":        "The sign-in was declined at the provider.",
		"auth_upstream":      "The sign-in provider did not answer as expected. Try again.",
		"auth_role":          "This account has no role that gives access.",
		"auth_form":          "The form expired. Reload the page and try again.",
		"auth_internal":      "Internal error while signing in. Try again.",
	},
}

// language picks pt or en: ?lang= (remembered in a cookie), then the cookie, then
// the browser's Accept-Language, then KUMAGATE_LANG.
func (s *server) language(w http.ResponseWriter, r *http.Request) string {
	if l := r.URL.Query().Get("lang"); translations[l] != nil {
		http.SetCookie(w, &http.Cookie{Name: langCookie, Value: l, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}) // served over HTTPS behind the proxy
		return l
	}
	if c, err := r.Cookie(langCookie); err == nil && translations[c.Value] != nil {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if base := strings.SplitN(tag, "-", 2)[0]; translations[base] != nil {
			return base
		}
	}
	return s.cfg.lang
}
