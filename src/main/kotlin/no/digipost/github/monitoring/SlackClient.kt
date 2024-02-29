package no.digipost.github.monitoring

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

class SlackClient(private val webhookUrl: String) {

    private val logger: Logger = LoggerFactory.getLogger("no.digipost.github.monitoring.SlackClient")
    private val client: HttpClient = HttpClient.newBuilder().build()

    fun sendToSlack(vulnerability: Vulnerability) {
        val request = slackRequest("Ny sårbarhet: ${toSlackInformation(vulnerability)}")
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 200) {
            logger.warn("Failed to report new vulnerability to slack. Status code ${response.statusCode()}, body: ${response.body()}")
        }
    }

    private fun toSlackInformation(vulnerability: Vulnerability): String {
        return "*${vulnerability.severity.name} (${vulnerability.score})* " +
                "<https://nvd.nist.gov/vuln/detail/${vulnerability.CVE}|${vulnerability.CVE}>, " +
                "package name: ${vulnerability.packageName}"
    }

    private fun slackRequest(message: String): HttpRequest {
        return HttpRequest
            .newBuilder()
            .uri(URI.create(webhookUrl))
            .POST(HttpRequest.BodyPublishers.ofString("{ \"text\": \"$message\"}"))
            .header("Content-Type", "application/json")
            .build()
    }
}