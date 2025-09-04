import os
import openpyxl
import logging
import pandas as pd
from django.http import HttpResponse
from django.db.models import Q, Prefetch, Max
from io import BytesIO
from django.db.models import Case, When, Value, CharField
import datetime
from django.db import transaction

from ...models import (runs, CVSSData, sw_branches, e_releases, current_sw_state, 
                      current_sw_state_comments, CVE, CPEEntry, sw_components)

logger = logging.getLogger("general")


def vuln_report(request):
    """
    Optimized vulnerability report generation with comprehensive matrix view
    """
    if request.method != "GET":
        return HttpResponse("Method not allowed", status=405)
    
    try:
        report_method = request.GET.get("report_method")
        r_id = request.GET.get("filter")
        
        if not report_method or not r_id:
            return HttpResponse("Missing required parameters", status=400)
        
        # Route to appropriate report generator
        if report_method == "project_level":
            return generate_project_level_report(request, r_id)
        elif report_method == "branch_level":
            return generate_branch_level_report(request, r_id)
        elif report_method == "component_level":
            return generate_component_level_report(request, r_id)
        elif report_method == "release_level":
            return generate_release_level_report(request, r_id)
        else:
            return HttpResponse("Invalid report method", status=400)
            
    except Exception as e:
        logger.error(f"Error in vuln_report: {str(e)}")
        return HttpResponse("Internal server error", status=500)


def generate_project_level_report(request, r_id):
    """
    Generate comprehensive project-level matrix report
    """
    try:
        runs_instance = runs.objects.select_related(
            'sw_branch_id__project_id'
        ).get(id=r_id)
        project = runs_instance.sw_branch_id.project_id
        
        # Get all branches with their latest releases and components
        branches_data = get_project_structure(project)
        
        # Get all unique CVEs across the project
        all_cves = get_unique_cves_for_project(project)
        
        # Build comprehensive matrix
        result_df = build_project_matrix(branches_data, all_cves)
        
        file_name = f"{project.project_name}_comprehensive_report.xlsx"
        return create_excel_response(result_df, file_name, "Project Report")
        
    except runs.DoesNotExist:
        return HttpResponse("Run not found", status=404)
    except Exception as e:
        logger.error(f"Error in generate_project_level_report: {str(e)}")
        return HttpResponse("Error generating project report", status=500)


def generate_branch_level_report(request, r_id):
    """
    Generate comprehensive branch-level matrix report
    """
    try:
        runs_instance = runs.objects.select_related('sw_branch_id').get(id=r_id)
        branch = runs_instance.sw_branch_id
        
        # Get branch structure (components or releases)
        branch_data = get_branch_structure(branch)
        
        # Get all unique CVEs for this branch
        all_cves = get_unique_cves_for_branch(branch)
        
        # Build branch matrix
        result_df = build_branch_matrix(branch_data, all_cves)
        
        file_name = f"{branch.project_id.project_name}_{branch.name}_comprehensive_report.xlsx"
        return create_excel_response(result_df, file_name, "Branch Report")
        
    except runs.DoesNotExist:
        return HttpResponse("Run not found", status=404)
    except Exception as e:
        logger.error(f"Error in generate_branch_level_report: {str(e)}")
        return HttpResponse("Error generating branch report", status=500)


def generate_component_level_report(request, r_id):
    """
    Generate component-level report showing all releases
    """
    try:
        # Assuming r_id refers to a component run or component_id is passed separately
        component_id = request.GET.get("component_id", r_id)
        component = sw_components.objects.select_related(
            'sw_branch__project_id'
        ).get(id=component_id)
        
        # Get all releases for this component
        releases = get_component_releases(component)
        
        # Get all unique CVEs for this component
        all_cves = get_unique_cves_for_component(component)
        
        # Build component matrix
        result_df = build_component_matrix(releases, all_cves)
        
        project_name = component.sw_branch.project_id.project_name
        branch_name = component.sw_branch.name
        file_name = f"{project_name}_{branch_name}_{component.component_name}_comprehensive_report.xlsx"
        
        return create_excel_response(result_df, file_name, "Component Report")
        
    except sw_components.DoesNotExist:
        return HttpResponse("Component not found", status=404)
    except Exception as e:
        logger.error(f"Error in generate_component_level_report: {str(e)}")
        return HttpResponse("Error generating component report", status=500)


def generate_release_level_report(request, r_id):
    """
    Generate detailed release-level report (existing functionality)
    """
    try:
        e_release_instance = e_releases.objects.get(id=r_id)
        filter_method = request.GET.get("filter_method")
        filter_dict = None
        
        if filter_method:
            filter_dict = request.GET.dict()
        
        result_df, file_name = vuln_report_generate(e_release_instance, filter_dict)
        return create_excel_response(result_df, file_name, "Release Report")
        
    except e_releases.DoesNotExist:
        return HttpResponse("Release not found", status=404)
    except Exception as e:
        logger.error(f"Error in generate_release_level_report: {str(e)}")
        return HttpResponse("Error generating release report", status=500)


def get_project_structure(project):
    """
    Get optimized project structure with latest releases
    """
    branches = sw_branches.objects.filter(project_id=project).prefetch_related(
        Prefetch('sw_components_set', queryset=sw_components.objects.all()),
        Prefetch('e_releases_set', queryset=e_releases.objects.filter(latest=True))
    )
    
    structure = {}
    for branch in branches:
        components = branch.sw_components_set.all()
        if components.exists():
            # Branch has components
            structure[branch.name] = {
                'type': 'branch_with_components',
                'components': {}
            }
            for component in components:
                latest_release = e_releases.objects.filter(
                    sw_component=component, latest=True
                ).first()
                if latest_release:
                    structure[branch.name]['components'][component.component_name] = latest_release
        else:
            # Branch without components
            latest_release = e_releases.objects.filter(
                sw_branch_id=branch, sw_component__isnull=True, latest=True
            ).first()
            if latest_release:
                structure[branch.name] = {
                    'type': 'branch_direct',
                    'release': latest_release
                }
    
    return structure


def get_branch_structure(branch):
    """
    Get branch structure with all releases or components
    """
    components = sw_components.objects.filter(sw_branch=branch)
    
    if components.exists():
        # Branch has components - get latest release for each
        structure = {'type': 'components', 'data': {}}
        for component in components:
            latest_release = e_releases.objects.filter(
                sw_component=component, latest=True
            ).first()
            if latest_release:
                structure['data'][component.component_name] = latest_release
    else:
        # Branch has direct releases
        releases = e_releases.objects.filter(
            sw_branch_id=branch, sw_component__isnull=True
        ).order_by('-creation_date')
        structure = {'type': 'releases', 'data': {}}
        for release in releases:
            structure['data'][release.e_release_version] = release
    
    return structure


def get_component_releases(component):
    """
    Get all releases for a component
    """
    return e_releases.objects.filter(sw_component=component).order_by('-creation_date')


def get_unique_cves_for_project(project):
    """
    Get all unique CVEs across the entire project efficiently
    """
    # Get latest runs for all releases in the project
    latest_runs = runs.objects.filter(
        sw_branch_id__project_id=project
    ).select_related('e_release_id')
    
    # Get all CVEs from these runs
    cve_data = current_sw_state.objects.filter(
        last_modified_run_id__in=latest_runs
    ).select_related('cve_id').values(
        'cve_id', 'descriptions', 'cvss_score', 'CVSS_Priority', 
        'Analysis_Priority', 'tool_state'
    ).distinct('cve_id')
    
    return {item['cve_id']: item for item in cve_data}


def get_unique_cves_for_branch(branch):
    """
    Get all unique CVEs for a specific branch with CPE data
    """
    latest_runs = runs.objects.filter(sw_branch_id=branch)
    
    cve_queryset = current_sw_state.objects.filter(
        last_modified_run_id__in=latest_runs
    ).select_related('cve_id').prefetch_related('cpe_string')
    
    cve_data = {}
    for cve_state in cve_queryset:
        cve_id = cve_state.cve_id
        if cve_id not in cve_data:
            # Get CPE information
            cpe_info = get_cpe_data_for_matrix(cve_state)
            
            cve_data[cve_id] = {
                'cve_id': cve_id,
                'descriptions': cve_state.descriptions,
                'cvss_score': cve_state.cvss_score,
                'CVSS_Priority': cve_state.CVSS_Priority,
                'Analysis_Priority': cve_state.Analysis_Priority,
                'tool_state': cve_state.tool_state,
                'cpe_string': cpe_info.get('cpe_string', ''),
                'sw_name': cpe_info.get('sw_name', ''),
                'sw_version': cpe_info.get('sw_version', ''),
                'architecture': cpe_info.get('architecture', ''),
            }
    
    return cve_data


def get_unique_cves_for_component(component):
    """
    Get all unique CVEs for a specific component with CPE data
    """
    releases = e_releases.objects.filter(sw_component=component)
    latest_runs = runs.objects.filter(e_release_id__in=releases)
    
    cve_queryset = current_sw_state.objects.filter(
        last_modified_run_id__in=latest_runs
    ).select_related('cve_id').prefetch_related('cpe_string')
    
    cve_data = {}
    for cve_state in cve_queryset:
        cve_id = cve_state.cve_id
        if cve_id not in cve_data:
            # Get CPE information
            cpe_info = get_cpe_data_for_matrix(cve_state)
            
            cve_data[cve_id] = {
                'cve_id': cve_id,
                'descriptions': cve_state.descriptions,
                'cvss_score': cve_state.cvss_score,
                'CVSS_Priority': cve_state.CVSS_Priority,
                'Analysis_Priority': cve_state.Analysis_Priority,
                'tool_state': cve_state.tool_state,
                'cpe_string': cpe_info.get('cpe_string', ''),
                'sw_name': cpe_info.get('sw_name', ''),
                'sw_version': cpe_info.get('sw_version', ''),
                'architecture': cpe_info.get('architecture', ''),
            }
    
    return cve_data


def get_cpe_data_for_matrix(cve_state):
    """
    Get CPE information from sw_bom_entries for matrix reports
    """
    try:
        # Get CPE strings associated with this CVE state
        cpe_entries = cve_state.cpe_string.all()
        if cpe_entries.exists():
            # Take the first CPE entry (or you could aggregate multiple)
            first_cpe = cpe_entries.first()
            return {
                'cpe_string': first_cpe.cpe_string,
                'sw_name': first_cpe.sw_name,
                'sw_version': first_cpe.sw_version,
                'architecture': first_cpe.architecture,
            }
    except Exception as e:
        logger.error(f"Error getting CPE data for matrix: {str(e)}")
    
    return {
        'cpe_string': '',
        'sw_name': '',
        'sw_version': '',
        'architecture': '',
    }


def build_project_matrix(branches_data, all_cves):
    """
    Build comprehensive project matrix with CVEs vs Branches/Components
    """
    # Create base DataFrame with CVE information
    cve_list = []
    for cve_id, cve_data in all_cves.items():
        base_data = {
            'CVE ID': cve_id,
            'Description': cve_data.get('descriptions', ''),
            'CVSS Score': cve_data.get('cvss_score', ''),
            'CVSS Priority': cve_data.get('CVSS_Priority', ''),
            'Analysis Priority': cve_data.get('Analysis_Priority', ''),
        }
        
        # Add columns for each branch/component
        for branch_name, branch_info in branches_data.items():
            if branch_info['type'] == 'branch_with_components':
                for comp_name, release in branch_info['components'].items():
                    col_name = f"{branch_name}_{comp_name}"
                    status = get_cve_status_for_release(cve_id, release)
                    base_data[col_name] = status
            else:
                status = get_cve_status_for_release(cve_id, branch_info['release'])
                base_data[branch_name] = status
        
        cve_list.append(base_data)
    
    return pd.DataFrame(cve_list)


def build_branch_matrix(branch_data, all_cves):
    """
    Build branch-level matrix
    """
    cve_list = []
    for cve_id, cve_data in all_cves.items():
        base_data = {
            'CVE ID': cve_id,
            'Description': cve_data.get('descriptions', ''),
            'CVSS Score': cve_data.get('cvss_score', ''),
            'CVSS Priority': cve_data.get('CVSS_Priority', ''),
            'Analysis Priority': cve_data.get('Analysis_Priority', ''),
        }
        
        # Add columns for each component/release
        for name, release in branch_data['data'].items():
            status = get_cve_status_for_release(cve_id, release)
            base_data[name] = status
        
        cve_list.append(base_data)
    
    return pd.DataFrame(cve_list)


def build_component_matrix(releases, all_cves):
    """
    Build component-level matrix showing all releases
    """
    cve_list = []
    for cve_id, cve_data in all_cves.items():
        base_data = {
            'CVE ID': cve_id,
            'Description': cve_data.get('descriptions', ''),
            'CVSS Score': cve_data.get('cvss_score', ''),
            'CVSS Priority': cve_data.get('CVSS_Priority', ''),
            'Analysis Priority': cve_data.get('Analysis_Priority', ''),
        }
        
        # Add columns for each release
        for release in releases:
            status = get_cve_status_for_release(cve_id, release)
            base_data[release.e_release_version] = status
        
        cve_list.append(base_data)
    
    return pd.DataFrame(cve_list)


def get_cve_status_for_release(cve_id, release):
    """
    Get CVE status for specific release efficiently
    """
    if not release:
        return "N/A"
    
    try:
        run_obj = runs.objects.filter(e_release_id=release).first()
        if not run_obj:
            return "No Run"
        
        cve_state = current_sw_state.objects.filter(
            cve_id=cve_id, 
            last_modified_run_id=run_obj
        ).first()
        
        if not cve_state:
            return "Not Found"
        
        # Return readable status
        status_map = {
            1: "New", 2: "Open", 3: "Accepted", 4: "Fix Requested",
            5: "Fixed: Verified", 6: "Fixed: Version Increment",
            7: "SA: False Positive", 8: "Rejected: False Positive",
            9: "Rejected: Not Affected", 10: "Not Affected",
            11: "TBC", 12: "Fixed"
        }
        
        return status_map.get(cve_state.tool_state, "Unknown")
        
    except Exception as e:
        logger.error(f"Error getting CVE status: {str(e)}")
        return "Error"


def create_excel_response(df, file_name, sheet_name="Report"):
    """
    Create optimized Excel response with formatting
    """
    try:
        if df.empty:
            df = pd.DataFrame({"Message": ["No data available"]})
        
        # Create Excel file in memory
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)
            
            # Get workbook and worksheet for formatting
            workbook = writer.book
            worksheet = writer.sheets[sheet_name]
            
            # Auto-adjust column widths
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)  # Cap at 50
                worksheet.column_dimensions[column_letter].width = adjusted_width
        
        output.seek(0)
        
        # Create HTTP response
        response = HttpResponse(
            output.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        
        # Log success
        logger.info(f"Report generated successfully: {file_name}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error creating Excel response: {str(e)}")
        return HttpResponse("Error creating Excel file", status=500)


def report_filter(cve_dict, current_sw_state_instance):
    """
    Optimized filtering function with error handling
    """
    try:
        # Extract filter parameters
        cve_search = cve_dict.get("cve_search", "").strip()
        severity_search = cve_dict.get("Severity_search", "")
        version_search = cve_dict.get("version_search", "")
        tool_status_search = cve_dict.get("tool_status_search", "")
        fixedin_search = cve_dict.get('fixedin_search', "")
        created_date = cve_dict.get("created_at", "")
        checked_cves = cve_dict.get("checked_cves", "")
        
        # Apply CVE ID filter
        if cve_search:
            current_sw_state_instance = apply_cve_filter(current_sw_state_instance, cve_search)
        
        # Apply severity filter
        if severity_search:
            current_sw_state_instance = apply_severity_filter(current_sw_state_instance, severity_search)
        
        # Apply tool status filter
        if tool_status_search:
            tool_status_list = [int(x.strip()) for x in tool_status_search.split(",") if x.strip().isdigit()]
            if tool_status_list:
                current_sw_state_instance = current_sw_state_instance.filter(tool_state__in=tool_status_list)
        
        # Apply other filters...
        if version_search:
            current_sw_state_instance = current_sw_state_instance.filter(
                first_detected_at__e_release_version__icontains=version_search
            )
        
        if fixedin_search and len(fixedin_search) > 1:
            current_sw_state_instance = current_sw_state_instance.filter(
                closed__icontains=fixedin_search
            )
        
        if created_date:
            try:
                target_date = datetime.datetime.strptime(created_date, "%Y-%m-%d")
                start = target_date
                end = target_date + datetime.timedelta(days=1)
                current_sw_state_instance = current_sw_state_instance.filter(
                    created_at__gte=start, created_at__lt=end
                )
            except ValueError:
                pass  # Invalid date format, skip filter
        
        if checked_cves:
            cve_list = [x.strip() for x in checked_cves.split(",") if x.strip()]
            if cve_list:
                current_sw_state_instance = current_sw_state_instance.filter(cve_id__in=cve_list)
        
        return current_sw_state_instance
        
    except Exception as e:
        logger.error(f"Error in report_filter: {str(e)}")
        return current_sw_state_instance


def apply_cve_filter(queryset, cve_search):
    """
    Apply CVE-specific filters with error handling
    """
    try:
        if ":" in cve_search:
            parts = cve_search.split(":")
            filter_type = parts[0].lower()
            filter_value = parts[1] if len(parts) > 1 else ""
            
            if filter_type == "av":  # Attack Vector
                cvss_cves = CVSSData.objects.filter(
                    attack_vector__iexact=filter_value
                ).values_list("cve_id", flat=True)
                return queryset.filter(cve_id__in=cvss_cves)
            
            elif filter_type == "desc":  # Description
                return queryset.filter(descriptions__icontains=filter_value)
            
        elif cve_search.lower() == "kb":
            return queryset.filter(last_modified_by_knowledgebase=1)
        
        elif cve_search.lower() == "cavd":
            return queryset.exclude(cavd_no__isnull=True).exclude(cavd_no="")
        
        elif cve_search.lower() in ["fp", "false positive"]:
            return queryset.filter(false_positive_reason__isnull=False).exclude(false_positive_reason='')
        
        elif cve_search.lower() in ["tp", "true positive"]:
            return queryset.filter(true_positive_reason__isnull=False).exclude(true_positive_reason='')
        
        else:
            return queryset.filter(cve_id__icontains=cve_search)
    
    except Exception as e:
        logger.error(f"Error in apply_cve_filter: {str(e)}")
        return queryset


def apply_severity_filter(queryset, severity_search):
    """
    Apply severity filters with error handling
    """
    try:
        severity_parts = [x.strip() for x in severity_search.split(",")]
        severity_list = [x for x in severity_parts if not x.isdigit() and x != "none"]
        severity_list = ["0" if x == "none" else x for x in severity_list]
        score_list = [float(x) for x in severity_parts if x.replace(".", "").isdigit()]
        
        q_filter = Q()
        if severity_list:
            q_filter |= Q(CVSS_Priority__in=severity_list)
        if score_list:
            q_filter |= Q(cvss_score__in=score_list)
        
        if q_filter:
            return queryset.filter(q_filter)
        
        return queryset
        
    except Exception as e:
        logger.error(f"Error in apply_severity_filter: {str(e)}")
        return queryset


def vuln_report_generate(e_release_id, filter_dict=None):
    """
    Optimized vulnerability report generation for single release
    """
    try:
        # Get run with proper error handling
        run_id = runs.objects.filter(e_release_id=e_release_id).order_by('-id').first()
        if not run_id:
            return pd.DataFrame(), "no_data.xlsx"
        
        # Get queryset with optimized queries
        queryset = current_sw_state.objects.filter(
            last_modified_run_id=run_id
        ).select_related('cve_id').prefetch_related('cpe_string')
        
        # Apply filters if provided
        if filter_dict:
            queryset = report_filter(filter_dict, queryset)
        
        if not queryset.exists():
            return pd.DataFrame(), "no_data.xlsx"
        
        # Process data efficiently
        cve_data = []
        for cve_state in queryset:
            data_row = process_cve_data(cve_state)
            if data_row:
                cve_data.append(data_row)
        
        if not cve_data:
            return pd.DataFrame(), "no_data.xlsx"
        
        # Create DataFrame
        df = pd.DataFrame(cve_data)
        
        # Generate filename
        project_name = run_id.sw_branch_id.project_id.project_name
        sw_name = run_id.sw_branch_id.name
        e_release_version = run_id.e_release_id.e_release_version
        file_name = f"{project_name}_{sw_name}_{e_release_version}.xlsx"
        
        return df, file_name
        
    except Exception as e:
        logger.error(f"Error in vuln_report_generate: {str(e)}")
        return pd.DataFrame(), "error.xlsx"


def process_cve_data(cve_state):
    """
    Process individual CVE data efficiently
    """
    try:
        cve_obj = cve_state.cve_id
        
        # Get CVSS data efficiently
        cvss_versions = get_cvss_data(cve_obj)
        
        # Get CPE data
        cpe_data = get_cpe_data(cve_state)
        
        # Get comments
        comments = get_comments(cve_state)
        
        # Determine primary CVSS
        primary_cvss_data = determine_primary_cvss(cvss_versions)
        
        # Build data dictionary
        data_dict = {
            "CVE ID": cve_state.cve_id,
            "CPE ID": cpe_data.get('cpe_id', ''),
            "Product": cpe_data.get('product', ''),
            "Version": cpe_data.get('version', ''),
            "Description": cve_state.descriptions or '',
            "Tool State": get_tool_state_name(cve_state.tool_state),
            "Analysis Priority": cve_state.Analysis_Priority or '',
            "Base Score": primary_cvss_data.get('score', ''),
            "Base Severity": primary_cvss_data.get('severity', ''),
            "Attack Vector": primary_cvss_data.get('attack_vector', ''),
            "Primary CVSS": primary_cvss_data.get('version', ''),
            "Comments": comments,
            "Closed At": cve_state.closed or '',
            "JIRA Ticket": cve_state.jira_ticket or '',
            "STARC Ticket": cve_state.starc_ticket or '',
            "STARC Status": cve_state.starc_status or '',
        }
        
        # Add version-specific CVSS data
        for version in ['2.0', '3.0', '3.1', '4.0']:
            version_data = cvss_versions.get(version, {})
            data_dict.update({
                f"CVSS {version} Score": version_data.get('score', ''),
                f"CVSS {version} Severity": version_data.get('severity', ''),
                f"CVSS {version} Vector": version_data.get('vector', ''),
            })
        
        # Add reason fields if they exist
        if cve_state.true_positive_reason:
            data_dict["True Positive Reason"] = format_reason(cve_state.true_positive_reason)
        
        if cve_state.false_positive_reason:
            data_dict["False Positive Reason"] = format_reason(cve_state.false_positive_reason)
        
        return data_dict
        
    except Exception as e:
        logger.error(f"Error processing CVE {cve_state.cve_id}: {str(e)}")
        return None


def get_cvss_data(cve_obj):
    """
    Get CVSS data for all versions efficiently
    """
    cvss_data = {}
    try:
        cvss_objects = CVSSData.objects.filter(cve=cve_obj).order_by('-id')
        
        for cvss in cvss_objects:
            version = cvss.version
            if version not in cvss_data:  # Keep first (latest) entry for each version
                cvss_data[version] = {
                    'score': cvss.base_score,
                    'severity': cvss.base_severity,
                    'vector': cvss.vector_string,
                    'attack_vector': cvss.attack_vector,
                }
    except Exception as e:
        logger.error(f"Error getting CVSS data: {str(e)}")
    
    return cvss_data


def get_cpe_data(cve_state):
    """
    Get CPE information efficiently
    """
    try:
        cpe_strings = cve_state.cpe_string.all()
        if cpe_strings.exists():
            first_cpe = cpe_strings.first()
            try:
                cpe_entry = CPEEntry.objects.select_related(
                    'product', 'version'
                ).get(cpe_name=first_cpe.cpe_string)
                return {
                    'cpe_id': first_cpe.cpe_string,
                    'product': cpe_entry.product.name,
                    'version': cpe_entry.version.version,
                }
            except CPEEntry.DoesNotExist:
                return {'cpe_id': first_cpe.cpe_string, 'product': '', 'version': ''}
    except Exception as e:
        logger.error(f"Error getting CPE data: {str(e)}")
    
    return {'cpe_id': '', 'product': '', 'version': ''}


def get_comments(cve_state):
    """
    Get formatted comments efficiently
    """
    try:
        comments = current_sw_state_comments.objects.filter(
            cve_id=cve_state
        ).values_list('comment', flat=True)
        return '\n'.join([c for c in comments if c])
    except Exception as e:
        logger.error(f"Error getting comments: {str(e)}")
        return ""


def determine_primary_cvss(cvss_versions):
    """
    Determine primary CVSS version based on availability
    """
    priority_order = ['4.0', '3.1', '3.0', '2.0']
    
    for version in priority_order:
        if version in cvss_versions and cvss_versions[version]['score']:
            return {
                'version': f"V{version}",
                'score': cvss_versions[version]['score'],
                'severity': cvss_versions[version]['severity'],
                'attack_vector': cvss_versions[version]['attack_vector'],
            }
    
    return {'version': '', 'score': '', 'severity': '', 'attack_vector': ''}


def get_tool_state_name(tool_state):
    """
    Convert tool state number to readable name
    """
    status_map = {
        1: "New", 2: "Open", 3: "Accepted", 4: "Fix Requested",
        5: "Fixed: Verified", 6: "Fixed: Version Increment",
        7: "SA: False Positive", 8: "Rejected: False Positive",
        9: "Rejected: Not Affected", 10: "Not Affected",
        11: "TBC", 12: "Fixed"
    }
    return status_map.get(tool_state, "Unknown")


def format_reason(reason):
    """
    Format true/false positive reasons
    """
    if not reason:
        return ""
    
    try:
        parts = reason.split(" ")
        if len(parts) >= 2:
            return f"This CVE is about {parts[0]} and its related Config Name is {parts[1]} which is {'set' if 'true' in reason.lower() else 'not set'} according to config file"
        else:
            return f"This CVE is about {parts[0]} {'present' if 'true' in reason.lower() else 'not present'} in the compile log"
    except Exception:
        return reason


# Additional utility functions for performance optimization

@transaction.atomic
def bulk_get_cve_statuses(cve_ids, releases):
    """
    Bulk fetch CVE statuses for multiple releases to improve performance
    """
    # Get all relevant runs
    run_ids = []
    release_run_map = {}
    
    for release in releases:
        run_obj = runs.objects.filter(e_release_id=release).first()
        if run_obj:
            run_ids.append(run_obj.id)
            release_run_map[release.id] = run_obj.id
    
    # Bulk fetch all CVE states
    cve_states = current_sw_state.objects.filter(
        cve_id__in=cve_ids,
        last_modified_run_id__in=run_ids
    ).select_related('last_modified_run_id')
    
    # Organize results
    results = {}
    for state in cve_states:
        cve_id = state.cve_id
        run_id = state.last_modified_run_id.id
        
        # Find which release this belongs to
        for release_id, mapped_run_id in release_run_map.items():
            if mapped_run_id == run_id:
                if cve_id not in results:
                    results[cve_id] = {}
                results[cve_id][release_id] = get_tool_state_name(state.tool_state)
                break
    
    return results


def get_optimized_project_cve_matrix(project_id):
    """
    Ultra-optimized function to get project-wide CVE matrix
    Uses raw SQL for better performance on large datasets
    """
    from django.db import connection
    
    query = """
    SELECT DISTINCT
        css.cve_id,
        css.descriptions,
        css.cvss_score,
        css.CVSS_Priority,
        css.Analysis_Priority,
        css.tool_state,
        sb.name as branch_name,
        sc.component_name,
        er.e_release_version,
        er.id as release_id
    FROM current_sw_state css
    JOIN runs r ON css.last_modified_run_id = r.id
    JOIN e_releases er ON r.e_release_id = er.id
    JOIN sw_branches sb ON er.sw_branch_id = sb.id
    LEFT JOIN sw_components sc ON er.sw_component_id = sc.id
    WHERE sb.project_id = %s
    AND er.latest = true
    ORDER BY css.cve_id, sb.name, sc.component_name, er.e_release_version
    """
    
    with connection.cursor() as cursor:
        cursor.execute(query, [project_id])
        columns = [col[0] for col in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    return results


def cache_cvss_data():
    """
    Cache frequently accessed CVSS data to improve performance
    This can be called periodically or when needed
    """
    from django.core.cache import cache
    
    # Cache CVSS data for frequently accessed CVEs
    recent_cves = current_sw_state.objects.values_list('cve_id', flat=True).distinct()[:1000]
    
    cvss_cache = {}
    cvss_objects = CVSSData.objects.filter(cve_id__in=recent_cves).select_related('cve')
    
    for cvss in cvss_objects:
        cve_id = cvss.cve.id
        if cve_id not in cvss_cache:
            cvss_cache[cve_id] = {}
        
        cvss_cache[cve_id][cvss.version] = {
            'score': cvss.base_score,
            'severity': cvss.base_severity,
            'vector': cvss.vector_string,
            'attack_vector': cvss.attack_vector,
        }
    
    cache.set('cvss_bulk_data', cvss_cache, timeout=3600)  # Cache for 1 hour
    return cvss_cache


def get_cached_cvss_data(cve_id):
    """
    Get CVSS data from cache if available, otherwise fetch from DB
    """
    from django.core.cache import cache
    
    cached_data = cache.get('cvss_bulk_data', {})
    if cve_id in cached_data:
        return cached_data[cve_id]
    
    # Fallback to DB query
    return get_cvss_data(cve_id)


# Background task functions (can be used with Celery)

def generate_report_async(report_type, params):
    """
    Asynchronous report generation for large datasets
    Can be used with Celery or similar task queue
    """
    try:
        if report_type == 'project':
            # Generate project report in background
            result = generate_project_level_report_data(params)
        elif report_type == 'branch':
            result = generate_branch_level_report_data(params)
        elif report_type == 'component':
            result = generate_component_level_report_data(params)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Store result in cache or database for retrieval
        from django.core.cache import cache
        cache_key = f"report_{report_type}_{params.get('id', 'unknown')}"
        cache.set(cache_key, result, timeout=1800)  # 30 minutes
        
        return cache_key
        
    except Exception as e:
        logger.error(f"Error in async report generation: {str(e)}")
        raise


def check_report_status(cache_key):
    """
    Check if async report is ready
    """
    from django.core.cache import cache
    return cache.get(cache_key) is not None


def get_async_report(cache_key):
    """
    Retrieve completed async report
    """
    from django.core.cache import cache
    return cache.get(cache_key)


# API endpoint for checking report progress
def report_status_api(request):
    """
    API endpoint to check report generation status
    """
    cache_key = request.GET.get('cache_key')
    if not cache_key:
        return HttpResponse("Missing cache_key parameter", status=400)
    
    if check_report_status(cache_key):
        return JsonResponse({'status': 'completed', 'ready': True})
    else:
        return JsonResponse({'status': 'processing', 'ready': False})


# Enhanced error handling and logging
class ReportGenerationError(Exception):
    """Custom exception for report generation errors"""
    pass


def log_performance_metrics(func_name, start_time, record_count=0):
    """
    Log performance metrics for optimization
    """
    import time
    end_time = time.time()
    duration = end_time - start_time
    
    logger.info(f"Performance: {func_name} took {duration:.2f}s for {record_count} records")
    
    if duration > 30:  # Log slow queries
        logger.warning(f"Slow operation detected: {func_name} took {duration:.2f}s")


# Database connection optimization
def optimize_db_queries():
    """
    Optimize database queries for better performance
    """
    from django.db import connection
    
    # Set appropriate connection parameters
    with connection.cursor() as cursor:
        # Optimize for read-heavy operations
        cursor.execute("SET SESSION query_cache_type = ON")
        cursor.execute("SET SESSION query_cache_size = 67108864")  # 64MB
        
        # Optimize JOIN buffer
        cursor.execute("SET SESSION join_buffer_size = 8388608")  # 8MB


# Memory management for large datasets
def process_large_dataset_in_chunks(queryset, chunk_size=1000):
    """
    Process large datasets in chunks to avoid memory issues
    """
    total_count = queryset.count()
    processed = 0
    results = []
    
    while processed < total_count:
        chunk = list(queryset[processed:processed + chunk_size])
        if not chunk:
            break
            
        # Process chunk
        for item in chunk:
            result = process_cve_data(item)
            if result:
                results.append(result)
        
        processed += len(chunk)
        
        # Log progress
        logger.info(f"Processed {processed}/{total_count} records")
    
    return results
