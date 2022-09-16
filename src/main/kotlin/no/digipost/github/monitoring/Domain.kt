package no.digipost.github.monitoring
import java.time.ZonedDateTime

data class Repository(
    val owner: String,
    val name: String,
    val language: String,
    val vulnerabilities: List<Vulnerability?> = emptyList()
){

    fun asString():String{
        return """-------------------------------
${this.owner}/${this.name} - ${this.language}
Antall sårbarheter: ${this.vulnerabilities.size}
    ${this.vulnerabilities.map { """Package: ${it?.packageName}
    Severity: ${it?.severity}
    Score: ${it?.score} / 10
    CVE: ${it?.CVE}
    """ }.joinToString("\n")}

"""
    }
}

data class Vulnerability(
    var severity: String,
    var createdAt: ZonedDateTime,
    var packageName: String,
    var advisoryDesctiption: String,
    var score: Double,
    var CVE: String
)


