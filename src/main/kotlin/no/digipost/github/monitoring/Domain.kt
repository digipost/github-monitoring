package no.digipost.github.monitoring
import com.github.graphql.client.type.SecurityAdvisorySeverity
import com.google.gson.annotations.SerializedName
import java.time.ZonedDateTime

data class Repository(
    val owner: String,
    val name: String,
    val language: String,
    val vulnerabilities: List<Vulnerability> = emptyList(),
    val containerScanStats: ContainerScanStats? = null,
){

    fun asString():String{
        return """-------------------------------
${this.owner}/${this.name} - ${this.language}
Antall sårbarheter: ${this.vulnerabilities.size}
    ${this.vulnerabilities.map { """Package: ${it.packageName}
    Severity: ${it.severity.name}
    Score: ${it.score} / 10
    CVE: ${it.CVE}
    """ }.joinToString("\n")}

"""
    }
}

data class Vulnerability(
    var severity: SecurityAdvisorySeverity,
    var createdAt: String,
    var packageName: String,
    var score: Double,
    var CVE: String
)

data class ContainerScanStats(
    var passes: Boolean,
    var passPercentage: Double,
    var numberOfRuns: Int,
)

data class Workflows(
    val workflows: List<Workflow>
)

data class Workflow(
    val path: String
)

data class WorkflowRuns(
    @SerializedName("workflow_runs") val workflowRuns: List<WorkflowRun>
)

data class WorkflowRun(
    val name: String,
    val conclusion: String?,
    val event: String,
    @SerializedName("created_at") val createdAt: String
){
    fun isSuccess(): Boolean {
        return conclusion?.lowercase() == "success"
    }

    fun isScheduledContainerScan(): Boolean {
        return name.lowercase().contains("container scan") &&
        (conclusion?.lowercase() == "success" || conclusion?.lowercase() == "failure")
    }
}
