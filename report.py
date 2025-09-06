import os
import openpyxl
import logging
import pandas as pd
from django.http import HttpResponse, JsonResponse
from django.db.models import Q, Prefetch, Max, Case, When, Value, CharField
from io import BytesIO
import datetime
from django.db import transaction

from ...models import (runs, CVSSData, sw_branches, e_releases, current_sw_state, 
                      current_sw_state_comments, CVE, CPEEntry, sw_components, 
                      sw_bom_entries, jira_details)

logger = logging.getLogger("general")


def vuln_report(request):
    """
    Enhanced vulnerability report generation with comprehensive matrix view and alternative approaches
    """
    if request.method != "GET":
        return HttpResponse("Method not allowed", status=405)
    
    try:
        report_method = request.GET.get("report_method")
        r_id = request.GET.get("filter")
        format_type = request.GET.get("format", "hybrid")  # comprehensive, alternative, or hybrid
        
        if not report_method or not r_id:
            return HttpResponse("Missing required parameters", status=400)
        
        logger.info(f"Report request: method={report_method}, id={r_id}, format={format_type}")
        
        # Route to appropriate report generator based on format
        if format_type == "alternative":
            return generate_alternative_format_report(request, report_method, r_id)
        elif format_type == "comprehensive":
            return generate_comprehensive_matrix_report(request, report_method, r_id)
        else:  # hybrid format (default)
            return generate_hybrid_format_report(request, report_method, r_id)
            
    except Exception as e:
        logger.error(f"Error in vuln_report: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return HttpResponse("Internal server error", status=500)


def generate_hybrid_format_report(request, report_method, r_id):
    """
    Generate hybrid format reports - simplified comprehensive first sheet + detailed alternative sheets
    """
    if report_method == "project_level":
        return generate_project_hybrid_report(request, r_id)
    elif report_method == "branch_level":
        return generate_branch_hybrid_report(request, r_id)
    elif report_method == "component_level":
        return generate_component_hybrid_report(request, r_id)
    elif report_method == "release_level":
        return generate_release_level_report(request, r_id)
    else:
        return HttpResponse("Invalid report method", status=400)


# HYBRID APPROACH IMPLEMENTATIONS

def generate_project_hybrid_report(request, r_id):
    """
    Generate hybrid project report: simplified comprehensive + detailed alternative sheets
    """
    try:
        runs_instance = runs.objects.select_related('sw_branch_id__project_id').get(id=r_id)
        project = runs_instance.sw_branch_id.project_id
        
        logger.info(f"Generating hybrid project report for: {project.project_name}")
        
        # Get data
        branches_data = get_project_structure_comprehensive(project)
        all_cves = get_unique_cves_for_project_comprehensive(project)
        
        # Create hybrid sheets
        sheets_data = create_hybrid_project_sheets(branches_data, all_cves)
        
        file_name = f"{project.project_name}_hybrid_report.xlsx"
        return create_multi_sheet_excel_response(sheets_data, file_name)
        
    except Exception as e:
        logger.error(f"Error in hybrid project report: {str(e)}")
        return HttpResponse("Error generating hybrid project report", status=500)


def create_hybrid_project_sheets(branches_data, all_cves):
    """
    Create hybrid project sheets: simplified comprehensive + detailed alternative
    """
    sheets = {}
    
    # Sheet 1: Simplified Comprehensive Matrix (CVE + CPE + Status + Comments only)
    comprehensive_data = []
    for cve_id, cve_data in all_cves.items():
        row = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'SW Version': cve_data['sw_version'],
            'Architecture': cve_data['architecture'],
            'CVSS Score': cve_data['cvss_score'],
            'CVSS Priority': cve_data['CVSS_Priority'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        # Add simplified columns for each branch/component (Status and Comments only)
        for branch_name, branch_info in branches_data.items():
            if branch_info['type'] == 'branch_with_components':
                for comp_name, release in branch_info['components'].items():
                    col_prefix = f"{branch_name}_{comp_name}"
                    details = get_comprehensive_release_details(cve_id, release)
                    row[f"{col_prefix}_Status"] = details['status']
                    row[f"{col_prefix}_Comments"] = details['comments']
            else:
                col_prefix = branch_name
                details = get_comprehensive_release_details(cve_id, branch_info['release'])
                row[f"{col_prefix}_Status"] = details['status']
                row[f"{col_prefix}_Comments"] = details['comments']
        
        comprehensive_data.append(row)
    
    sheets['Comprehensive_Summary'] = pd.DataFrame(comprehensive_data)
    
    # Sheet 2: Detailed View (Vertical Format with ALL columns)
    detailed_data = []
    for cve_id, cve_data in all_cves.items():
        for branch_name, branch_info in branches_data.items():
            if branch_info['type'] == 'branch_with_components':
                for comp_name, release in branch_info['components'].items():
                    details = get_comprehensive_release_details(cve_id, release)
                    detailed_data.append({
                        'CVE ID': cve_id,
                        'Description': cve_data['descriptions'],
                        'CPE String': cve_data['cpe_string'],
                        'SW Name': cve_data['sw_name'],
                        'SW Version': cve_data['sw_version'],
                        'Architecture': cve_data['architecture'],
                        'Branch': branch_name,
                        'Component': comp_name,
                        'Release': release.e_release_version if release else '',
                        'Status': details['status'],
                        'CVSS Score': cve_data['cvss_score'],
                        'CVSS Priority': cve_data['CVSS_Priority'],
                        'Analysis Priority': cve_data['Analysis_Priority'],
                        'Attack Vector': cve_data['attack_vector'],
                        'Comments': details['comments'],
                        'Closed At': details['closed_at'],
                        'JIRA Ticket': details['jira_ticket'],
                        'JIRA Status': details['jira_status'],
                        'STARC Ticket': details['starc_ticket'],
                        'STARC Status': details['starc_status'],
                        'True Positive': details['true_positive_reason'],
                        'False Positive': details['false_positive_reason'],
                        'KB Modified': details['kb_modified'],
                        'CAVD No': details['cavd_no'],
                    })
            else:
                details = get_comprehensive_release_details(cve_id, branch_info['release'])
                detailed_data.append({
                    'CVE ID': cve_id,
                    'Description': cve_data['descriptions'],
                    'CPE String': cve_data['cpe_string'],
                    'SW Name': cve_data['sw_name'],
                    'SW Version': cve_data['sw_version'],
                    'Architecture': cve_data['architecture'],
                    'Branch': branch_name,
                    'Component': '',
                    'Release': branch_info['release'].e_release_version if branch_info['release'] else '',
                    'Status': details['status'],
                    'CVSS Score': cve_data['cvss_score'],
                    'CVSS Priority': cve_data['CVSS_Priority'],
                    'Analysis Priority': cve_data['Analysis_Priority'],
                    'Attack Vector': cve_data['attack_vector'],
                    'Comments': details['comments'],
                    'Closed At': details['closed_at'],
                    'JIRA Ticket': details['jira_ticket'],
                    'JIRA Status': details['jira_status'],
                    'STARC Ticket': details['starc_ticket'],
                    'STARC Status': details['starc_status'],
                    'True Positive': details['true_positive_reason'],
                    'False Positive': details['false_positive_reason'],
                    'KB Modified': details['kb_modified'],
                    'CAVD No': details['cavd_no'],
                })
    
    sheets['Full_Details'] = pd.DataFrame(detailed_data)
    
    # Sheet 3: CVE Summary (Unique CVEs with comprehensive info)
    cve_summary_data = []
    for cve_id, cve_data in all_cves.items():
        # Get CVSS data for all versions
        cvss_versions = get_all_cvss_versions(cve_id)
        
        cve_summary_data.append({
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'SW Version': cve_data['sw_version'],
            'Architecture': cve_data['architecture'],
            'CVSS Score': cve_data['cvss_score'],
            'CVSS Priority': cve_data['CVSS_Priority'],
            'Analysis Priority': cve_data['Analysis_Priority'],
            'Attack Vector': cve_data['attack_vector'],
            'CVSS 2.0 Score': cvss_versions.get('2.0', {}).get('score', ''),
            'CVSS 2.0 Severity': cvss_versions.get('2.0', {}).get('severity', ''),
            'CVSS 3.0 Score': cvss_versions.get('3.0', {}).get('score', ''),
            'CVSS 3.0 Severity': cvss_versions.get('3.0', {}).get('severity', ''),
            'CVSS 3.1 Score': cvss_versions.get('3.1', {}).get('score', ''),
            'CVSS 3.1 Severity': cvss_versions.get('3.1', {}).get('severity', ''),
            'CVSS 4.0 Score': cvss_versions.get('4.0', {}).get('score', ''),
            'CVSS 4.0 Severity': cvss_versions.get('4.0', {}).get('severity', ''),
        })
    
    sheets['CVE_Summary'] = pd.DataFrame(cve_summary_data)
    
    # Sheet 4+: Per-Branch Detailed Analysis
    for branch_name, branch_info in branches_data.items():
        branch_data = []
        for cve_id, cve_data in all_cves.items():
            if branch_info['type'] == 'branch_with_components':
                for comp_name, release in branch_info['components'].items():
                    details = get_comprehensive_release_details(cve_id, release)
                    if details['status'] not in ['N/A', 'Not Found']:
                        branch_data.append({
                            'CVE ID': cve_id,
                            'Component': comp_name,
                            'Release': release.e_release_version if release else '',
                            'Description': cve_data['descriptions'],
                            'CPE String': cve_data['cpe_string'],
                            'SW Name': cve_data['sw_name'],
                            'SW Version': cve_data['sw_version'],
                            'Status': details['status'],
                            'CVSS Score': cve_data['cvss_score'],
                            'CVSS Priority': cve_data['CVSS_Priority'],
                            'Attack Vector': cve_data['attack_vector'],
                            'Comments': details['comments'],
                            'Closed At': details['closed_at'],
                            'JIRA Ticket': details['jira_ticket'],
                            'JIRA Status': details['jira_status'],
                            'STARC Ticket': details['starc_ticket'],
                            'STARC Status': details['starc_status'],
                            'True Positive': details['true_positive_reason'],
                            'False Positive': details['false_positive_reason'],
                            'KB Modified': details['kb_modified'],
                            'CAVD No': details['cavd_no'],
                        })
            else:
                details = get_comprehensive_release_details(cve_id, branch_info['release'])
                if details['status'] not in ['N/A', 'Not Found']:
                    branch_data.append({
                        'CVE ID': cve_id,
                        'Component': 'Direct Release',
                        'Release': branch_info['release'].e_release_version if branch_info['release'] else '',
                        'Description': cve_data['descriptions'],
                        'CPE String': cve_data['cpe_string'],
                        'SW Name': cve_data['sw_name'],
                        'SW Version': cve_data['sw_version'],
                        'Status': details['status'],
                        'CVSS Score': cve_data['cvss_score'],
                        'CVSS Priority': cve_data['CVSS_Priority'],
                        'Attack Vector': cve_data['attack_vector'],
                        'Comments': details['comments'],
                        'Closed At': details['closed_at'],
                        'JIRA Ticket': details['jira_ticket'],
                        'JIRA Status': details['jira_status'],
                        'STARC Ticket': details['starc_ticket'],
                        'STARC Status': details['starc_status'],
                        'True Positive': details['true_positive_reason'],
                        'False Positive': details['false_positive_reason'],
                        'KB Modified': details['kb_modified'],
                        'CAVD No': details['cavd_no'],
                    })
        
        if branch_data:
            # Clean branch name for Excel sheet naming
            clean_branch_name = branch_name.replace('/', '_').replace('\\', '_')[:25]
            sheets[f'Branch_{clean_branch_name}'] = pd.DataFrame(branch_data)
    
    return sheets


def generate_branch_hybrid_report(request, r_id):
    """
    Generate hybrid branch-level report
    """
    try:
        runs_instance = runs.objects.select_related('sw_branch_id').get(id=r_id)
        branch = runs_instance.sw_branch_id
        
        branch_data = get_branch_structure_comprehensive(branch)
        all_cves = get_unique_cves_for_branch_comprehensive(branch)
        
        sheets_data = create_hybrid_branch_sheets(branch_data, all_cves, branch.name)
        
        file_name = f"{branch.project_id.project_name}_{branch.name}_hybrid.xlsx"
        return create_multi_sheet_excel_response(sheets_data, file_name)
        
    except Exception as e:
        logger.error(f"Error in hybrid branch report: {str(e)}")
        return HttpResponse("Error generating hybrid branch report", status=500)


def create_hybrid_branch_sheets(branch_data, all_cves, branch_name):
    """
    Create hybrid branch sheets
    """
    sheets = {}
    
    # Sheet 1: Simplified Comprehensive (Status + Comments only)
    comprehensive_data = []
    for cve_id, cve_data in all_cves.items():
        row = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'SW Version': cve_data['sw_version'],
            'CVSS Score': cve_data['cvss_score'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        for name, release in branch_data['data'].items():
            details = get_comprehensive_release_details(cve_id, release)
            row[f"{name}_Status"] = details['status']
            row[f"{name}_Comments"] = details['comments']
        
        comprehensive_data.append(row)
    
    sheets['Comprehensive_Summary'] = pd.DataFrame(comprehensive_data)
    
    # Sheet 2: Full Details
    detailed_data = []
    for cve_id, cve_data in all_cves.items():
        for name, release in branch_data['data'].items():
            details = get_comprehensive_release_details(cve_id, release)
            detailed_data.append({
                'CVE ID': cve_id,
                'Component/Release': name,
                'Description': cve_data['descriptions'],
                'CPE String': cve_data['cpe_string'],
                'SW Name': cve_data['sw_name'],
                'SW Version': cve_data['sw_version'],
                'Architecture': cve_data['architecture'],
                'Status': details['status'],
                'CVSS Score': cve_data['cvss_score'],
                'CVSS Priority': cve_data['CVSS_Priority'],
                'Attack Vector': cve_data['attack_vector'],
                'Comments': details['comments'],
                'Closed At': details['closed_at'],
                'JIRA Ticket': details['jira_ticket'],
                'JIRA Status': details['jira_status'],
                'STARC Ticket': details['starc_ticket'],
                'STARC Status': details['starc_status'],
                'True Positive': details['true_positive_reason'],
                'False Positive': details['false_positive_reason'],
                'KB Modified': details['kb_modified'],
                'CAVD No': details['cavd_no'],
            })
    
    sheets['Full_Details'] = pd.DataFrame(detailed_data)
    
    # Sheet 3: CVE Summary
    cve_summary_data = []
    for cve_id, cve_data in all_cves.items():
        cvss_versions = get_all_cvss_versions(cve_id)
        cve_summary_data.append({
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'CVSS Score': cve_data['cvss_score'],
            'Attack Vector': cve_data['attack_vector'],
            'CVSS 2.0 Score': cvss_versions.get('2.0', {}).get('score', ''),
            'CVSS 3.0 Score': cvss_versions.get('3.0', {}).get('score', ''),
            'CVSS 3.1 Score': cvss_versions.get('3.1', {}).get('score', ''),
            'CVSS 4.0 Score': cvss_versions.get('4.0', {}).get('score', ''),
        })
    
    sheets['CVE_Summary'] = pd.DataFrame(cve_summary_data)
    
    return sheets


def generate_component_hybrid_report(request, r_id):
    """
    Generate hybrid component-level report
    """
    try:
        component_id = request.GET.get("component_id", r_id)
        component = sw_components.objects.select_related('sw_branch__project_id').get(id=component_id)
        
        releases = e_releases.objects.filter(sw_component=component).order_by('-creation_date')
        all_cves = get_unique_cves_for_component_comprehensive(component)
        
        sheets_data = create_hybrid_component_sheets(releases, all_cves, component.component_name)
        
        project_name = component.sw_branch.project_id.project_name
        branch_name = component.sw_branch.name
        file_name = f"{project_name}_{branch_name}_{component.component_name}_hybrid.xlsx"
        
        return create_multi_sheet_excel_response(sheets_data, file_name)
        
    except Exception as e:
        logger.error(f"Error in hybrid component report: {str(e)}")
        return HttpResponse("Error generating hybrid component report", status=500)


def create_hybrid_component_sheets(releases, all_cves, component_name):
    """
    Create hybrid component sheets
    """
    sheets = {}
    
    # Sheet 1: Simplified Comprehensive
    comprehensive_data = []
    for cve_id, cve_data in all_cves.items():
        row = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'SW Version': cve_data['sw_version'],
            'CVSS Score': cve_data['cvss_score'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        for release in releases:
            details = get_comprehensive_release_details(cve_id, release)
            row[f"{release.e_release_version}_Status"] = details['status']
            row[f"{release.e_release_version}_Comments"] = details['comments']
        
        comprehensive_data.append(row)
    
    sheets['Comprehensive_Summary'] = pd.DataFrame(comprehensive_data)
    
    # Sheet 2: Full Details
    detailed_data = []
    for cve_id, cve_data in all_cves.items():
        for release in releases:
            details = get_comprehensive_release_details(cve_id, release)
            detailed_data.append({
                'CVE ID': cve_id,
                'Release': release.e_release_version,
                'Description': cve_data['descriptions'],
                'CPE String': cve_data['cpe_string'],
                'SW Name': cve_data['sw_name'],
                'SW Version': cve_data['sw_version'],
                'Architecture': cve_data['architecture'],
                'Status': details['status'],
                'CVSS Score': cve_data['cvss_score'],
                'CVSS Priority': cve_data['CVSS_Priority'],
                'Attack Vector': cve_data['attack_vector'],
                'Comments': details['comments'],
                'Closed At': details['closed_at'],
                'JIRA Ticket': details['jira_ticket'],
                'JIRA Status': details['jira_status'],
                'STARC Ticket': details['starc_ticket'],
                'STARC Status': details['starc_status'],
                'True Positive': details['true_positive_reason'],
                'False Positive': details['false_positive_reason'],
                'KB Modified': details['kb_modified'],
                'CAVD No': details['cavd_no'],
            })
    
    sheets['Full_Details'] = pd.DataFrame(detailed_data)
    
    # Sheet 3: CVE Summary
    cve_summary_data = []
    for cve_id, cve_data in all_cves.items():
        cvss_versions = get_all_cvss_versions(cve_id)
        cve_summary_data.append({
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'CVSS Score': cve_data['cvss_score'],
            'Attack Vector': cve_data['attack_vector'],
            'CVSS 2.0 Score': cvss_versions.get('2.0', {}).get('score', ''),
            'CVSS 3.0 Score': cvss_versions.get('3.0', {}).get('score', ''),
            'CVSS 3.1 Score': cvss_versions.get('3.1', {}).get('score', ''),
            'CVSS 4.0 Score': cvss_versions.get('4.0', {}).get('score', ''),
        })
    
    sheets['CVE_Summary'] = pd.DataFrame(cve_summary_data)
    
    return sheets


# COMPREHENSIVE MATRIX APPROACH (As Requested)

def generate_project_comprehensive_report(request, r_id):
    """
    Generate comprehensive project-level matrix report with all requested columns
    """
    try:
        runs_instance = runs.objects.select_related('sw_branch_id__project_id').get(id=r_id)
        project = runs_instance.sw_branch_id.project_id
        
        logger.info(f"Generating comprehensive project report for: {project.project_name}")
        
        # Get project structure and CVEs
        branches_data = get_project_structure_comprehensive(project)
        all_cves = get_unique_cves_for_project_comprehensive(project)
        
        # Build comprehensive matrix
        result_df = build_project_comprehensive_matrix(branches_data, all_cves)
        
        file_name = f"{project.project_name}_comprehensive_matrix.xlsx"
        return create_excel_response(result_df, file_name, "Comprehensive Project Matrix")
        
    except Exception as e:
        logger.error(f"Error in comprehensive project report: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return HttpResponse("Error generating comprehensive project report", status=500)


def get_project_structure_comprehensive(project):
    """
    Get project structure optimized for comprehensive matrix
    """
    try:
        branches = sw_branches.objects.filter(project_id=project).prefetch_related(
            'sw_components_set',
            Prefetch('e_releases_set', queryset=e_releases.objects.filter(latest=True))
        )
        
        structure = {}
        logger.info(f"Processing {branches.count()} branches")
        
        for branch in branches:
            components = sw_components.objects.filter(sw_branch=branch)
            
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
                        logger.info(f"Added component {component.component_name} with release {latest_release.e_release_version}")
            else:
                # Branch without components - direct releases
                latest_release = e_releases.objects.filter(
                    sw_branch_id=branch, sw_component__isnull=True, latest=True
                ).first()
                if latest_release:
                    structure[branch.name] = {
                        'type': 'branch_direct',
                        'release': latest_release
                    }
                    logger.info(f"Added branch {branch.name} with direct release {latest_release.e_release_version}")
        
        return structure
        
    except Exception as e:
        logger.error(f"Error getting project structure: {str(e)}")
        return {}


def get_unique_cves_for_project_comprehensive(project):
    """
    Get all unique CVEs with comprehensive data including CPE info from sw_bom_entries
    """
    try:
        # Get all runs for the project
        project_runs = runs.objects.filter(
            sw_branch_id__project_id=project
        ).select_related('e_release_id', 'sw_branch_id')
        
        logger.info(f"Found {project_runs.count()} runs for project")
        
        # Get CVE states with related data
        cve_states = current_sw_state.objects.filter(
            last_modified_run_id__in=project_runs
        ).select_related('cve_id').prefetch_related('cpe_string')
        
        cve_data = {}
        for cve_state in cve_states:
            cve_id = cve_state.cve_id
            if cve_id not in cve_data:
                # Get comprehensive CVE info
                cpe_info = get_comprehensive_cpe_data(cve_state)
                attack_vector = get_attack_vector_for_cve(cve_id)
                
                cve_data[cve_id] = {
                    'cve_id': cve_id,
                    'descriptions': cve_state.descriptions or '',
                    'cvss_score': cve_state.cvss_score or '',
                    'CVSS_Priority': cve_state.CVSS_Priority or '',
                    'Analysis_Priority': cve_state.Analysis_Priority or '',
                    'attack_vector': attack_vector,
                    'cpe_string': cpe_info.get('cpe_string', ''),
                    'sw_name': cpe_info.get('sw_name', ''),
                    'sw_version': cpe_info.get('sw_version', ''),
                    'architecture': cpe_info.get('architecture', ''),
                }
        
        logger.info(f"Processed {len(cve_data)} unique CVEs")
        return cve_data
        
    except Exception as e:
        logger.error(f"Error getting unique CVEs: {str(e)}")
        return {}


def get_comprehensive_cpe_data(cve_state):
    """
    Get comprehensive CPE data from sw_bom_entries table
    """
    try:
        # Get CPE entries from the many-to-many relationship
        cpe_entries = cve_state.cpe_string.all()
        if cpe_entries.exists():
            first_cpe = cpe_entries.first()
            return {
                'cpe_string': first_cpe.cpe_string or '',
                'sw_name': first_cpe.sw_name or '',
                'sw_version': first_cpe.sw_version or '',
                'architecture': first_cpe.architecture or '',
            }
    except Exception as e:
        logger.error(f"Error getting CPE data: {str(e)}")
    
    return {'cpe_string': '', 'sw_name': '', 'sw_version': '', 'architecture': ''}


def get_attack_vector_for_cve(cve_id):
    """
    Get attack vector from CVSS data
    """
    try:
        cve_obj = CVE.objects.get(id=cve_id)
        cvss_data = CVSSData.objects.filter(cve=cve_obj).order_by('-version', '-id').first()
        if cvss_data and cvss_data.attack_vector:
            return cvss_data.attack_vector
    except Exception as e:
        logger.error(f"Error getting attack vector for {cve_id}: {str(e)}")
    return ""


def build_project_comprehensive_matrix(branches_data, all_cves):
    """
    Build comprehensive project matrix with ALL requested columns per branch/component
    """
    logger.info(f"Building comprehensive matrix: {len(all_cves)} CVEs, {len(branches_data)} branches")
    
    cve_list = []
    for cve_id, cve_data in all_cves.items():
        # Base CVE information
        base_data = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'], 
            'SW Version': cve_data['sw_version'],
            'Architecture': cve_data['architecture'],
            'CVSS Score': cve_data['cvss_score'],
            'CVSS Priority': cve_data['CVSS_Priority'],
            'Analysis Priority': cve_data['Analysis_Priority'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        # Add comprehensive columns for each branch/component
        for branch_name, branch_info in branches_data.items():
            if branch_info['type'] == 'branch_with_components':
                # Branch with components - add columns for each component
                for comp_name, release in branch_info['components'].items():
                    col_prefix = f"{branch_name}_{comp_name}"
                    details = get_comprehensive_release_details(cve_id, release)
                    
                    # Add all 11 columns per component
                    base_data.update({
                        f"{col_prefix}_Status": details['status'],
                        f"{col_prefix}_Comments": details['comments'],
                        f"{col_prefix}_Closed_At": details['closed_at'],
                        f"{col_prefix}_JIRA_Ticket": details['jira_ticket'],
                        f"{col_prefix}_JIRA_Status": details['jira_status'],
                        f"{col_prefix}_STARC_Ticket": details['starc_ticket'],
                        f"{col_prefix}_STARC_Status": details['starc_status'],
                        f"{col_prefix}_True_Positive": details['true_positive_reason'],
                        f"{col_prefix}_False_Positive": details['false_positive_reason'],
                        f"{col_prefix}_KB_Modified": details['kb_modified'],
                        f"{col_prefix}_CAVD_No": details['cavd_no'],
                    })
            else:
                # Branch without components - add columns for branch directly
                col_prefix = branch_name
                details = get_comprehensive_release_details(cve_id, branch_info['release'])
                
                base_data.update({
                    f"{col_prefix}_Status": details['status'],
                    f"{col_prefix}_Comments": details['comments'],
                    f"{col_prefix}_Closed_At": details['closed_at'],
                    f"{col_prefix}_JIRA_Ticket": details['jira_ticket'],
                    f"{col_prefix}_JIRA_Status": details['jira_status'],
                    f"{col_prefix}_STARC_Ticket": details['starc_ticket'],
                    f"{col_prefix}_STARC_Status": details['starc_status'],
                    f"{col_prefix}_True_Positive": details['true_positive_reason'],
                    f"{col_prefix}_False_Positive": details['false_positive_reason'],
                    f"{col_prefix}_KB_Modified": details['kb_modified'],
                    f"{col_prefix}_CAVD_No": details['cavd_no'],
                })
        
        cve_list.append(base_data)
    
    df = pd.DataFrame(cve_list)
    logger.info(f"Created comprehensive matrix: {df.shape}")
    return df


def get_comprehensive_release_details(cve_id, release):
    """
    Get comprehensive CVE details for a specific release with ALL requested fields
    """
    default_response = {
        'status': 'N/A', 'comments': '', 'closed_at': '', 'jira_ticket': '',
        'jira_status': '', 'starc_ticket': '', 'starc_status': '',
        'true_positive_reason': '', 'false_positive_reason': '',
        'kb_modified': '', 'cavd_no': ''
    }
    
    if not release:
        return default_response
    
    try:
        # Get the run for this release
        run_obj = runs.objects.filter(e_release_id=release).first()
        if not run_obj:
            return {**default_response, 'status': 'No Run'}
        
        # Get CVE state for this run
        cve_state = current_sw_state.objects.filter(
            cve_id=cve_id,
            last_modified_run_id=run_obj
        ).first()
        
        if not cve_state:
            return {**default_response, 'status': 'Not Found'}
        
        # Get comments from current_sw_state_comments
        comments = current_sw_state_comments.objects.filter(
            cve_id=cve_state
        ).values_list('comment', flat=True)
        comment_str = ' | '.join([c for c in comments if c])
        
        # Get JIRA details
        jira_detail = jira_details.objects.filter(cve_id=cve_state).first()
        jira_status = jira_detail.jira_status if jira_detail else ''
        
        # Format knowledge base modification status
        kb_modified = ""
        if cve_state.last_modified_by_knowledgebase == 1:
            kb_modified = "KB Modified"
        elif cve_state.last_modified_by_knowledgebase == 2:
            kb_modified = "System Modified"
        
        # Get tool state name
        status_map = {
            1: "New", 2: "Open", 3: "Accepted", 4: "Fix Requested",
            5: "Fixed: Verified", 6: "Fixed: Version Increment",
            7: "SA: False Positive", 8: "Rejected: False Positive",
            9: "Rejected: Not Affected", 10: "Not Affected",
            11: "TBC", 12: "Fixed"
        }
        
        return {
            'status': status_map.get(cve_state.tool_state, 'Unknown'),
            'comments': comment_str,
            'closed_at': cve_state.closed or '',
            'jira_ticket': cve_state.jira_ticket or '',
            'jira_status': jira_status,
            'starc_ticket': cve_state.starc_ticket or '',
            'starc_status': cve_state.starc_status or '',
            'true_positive_reason': format_reason(cve_state.true_positive_reason) if cve_state.true_positive_reason else '',
            'false_positive_reason': format_reason(cve_state.false_positive_reason) if cve_state.false_positive_reason else '',
            'kb_modified': kb_modified,
            'cavd_no': cve_state.cavd_no or '',
        }
        
    except Exception as e:
        logger.error(f"Error getting release details for {cve_id}: {str(e)}")
        return {**default_response, 'status': 'Error'}


def generate_branch_comprehensive_report(request, r_id):
    """
    Generate comprehensive branch-level report
    """
    try:
        runs_instance = runs.objects.select_related('sw_branch_id').get(id=r_id)
        branch = runs_instance.sw_branch_id
        
        # Get branch structure
        branch_data = get_branch_structure_comprehensive(branch)
        all_cves = get_unique_cves_for_branch_comprehensive(branch)
        
        # Build matrix
        result_df = build_branch_comprehensive_matrix(branch_data, all_cves)
        
        file_name = f"{branch.project_id.project_name}_{branch.name}_comprehensive.xlsx"
        return create_excel_response(result_df, file_name, "Branch Comprehensive Report")
        
    except Exception as e:
        logger.error(f"Error in branch comprehensive report: {str(e)}")
        return HttpResponse("Error generating branch report", status=500)


def get_branch_structure_comprehensive(branch):
    """
    Get branch structure for comprehensive reporting
    """
    components = sw_components.objects.filter(sw_branch=branch)
    
    if components.exists():
        # Branch has components
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


def get_unique_cves_for_branch_comprehensive(branch):
    """
    Get unique CVEs for branch with comprehensive data
    """
    try:
        branch_runs = runs.objects.filter(sw_branch_id=branch)
        cve_states = current_sw_state.objects.filter(
            last_modified_run_id__in=branch_runs
        ).select_related('cve_id').prefetch_related('cpe_string')
        
        cve_data = {}
        for cve_state in cve_states:
            cve_id = cve_state.cve_id
            if cve_id not in cve_data:
                cpe_info = get_comprehensive_cpe_data(cve_state)
                attack_vector = get_attack_vector_for_cve(cve_id)
                
                cve_data[cve_id] = {
                    'cve_id': cve_id,
                    'descriptions': cve_state.descriptions or '',
                    'cvss_score': cve_state.cvss_score or '',
                    'CVSS_Priority': cve_state.CVSS_Priority or '',
                    'Analysis_Priority': cve_state.Analysis_Priority or '',
                    'attack_vector': attack_vector,
                    'cpe_string': cpe_info.get('cpe_string', ''),
                    'sw_name': cpe_info.get('sw_name', ''),
                    'sw_version': cpe_info.get('sw_version', ''),
                    'architecture': cpe_info.get('architecture', ''),
                }
        
        return cve_data
        
    except Exception as e:
        logger.error(f"Error getting branch CVEs: {str(e)}")
        return {}


def build_branch_comprehensive_matrix(branch_data, all_cves):
    """
    Build comprehensive branch matrix
    """
    cve_list = []
    for cve_id, cve_data in all_cves.items():
        base_data = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'SW Version': cve_data['sw_version'],
            'Architecture': cve_data['architecture'],
            'CVSS Score': cve_data['cvss_score'],
            'CVSS Priority': cve_data['CVSS_Priority'],
            'Analysis Priority': cve_data['Analysis_Priority'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        # Add comprehensive columns for each component/release
        for name, release in branch_data['data'].items():
            details = get_comprehensive_release_details(cve_id, release)
            col_prefix = name
            
            base_data.update({
                f"{col_prefix}_Status": details['status'],
                f"{col_prefix}_Comments": details['comments'],
                f"{col_prefix}_Closed_At": details['closed_at'],
                f"{col_prefix}_JIRA_Ticket": details['jira_ticket'],
                f"{col_prefix}_JIRA_Status": details['jira_status'],
                f"{col_prefix}_STARC_Ticket": details['starc_ticket'],
                f"{col_prefix}_STARC_Status": details['starc_status'],
                f"{col_prefix}_True_Positive": details['true_positive_reason'],
                f"{col_prefix}_False_Positive": details['false_positive_reason'],
                f"{col_prefix}_KB_Modified": details['kb_modified'],
                f"{col_prefix}_CAVD_No": details['cavd_no'],
            })
        
        cve_list.append(base_data)
    
    return pd.DataFrame(cve_list)


def generate_component_comprehensive_report(request, r_id):
    """
    Generate comprehensive component-level report
    """
    try:
        component_id = request.GET.get("component_id", r_id)
        component = sw_components.objects.select_related('sw_branch__project_id').get(id=component_id)
        
        # Get all releases for component
        releases = e_releases.objects.filter(sw_component=component).order_by('-creation_date')
        all_cves = get_unique_cves_for_component_comprehensive(component)
        
        # Build matrix
        result_df = build_component_comprehensive_matrix(releases, all_cves)
        
        project_name = component.sw_branch.project_id.project_name
        branch_name = component.sw_branch.name
        file_name = f"{project_name}_{branch_name}_{component.component_name}_comprehensive.xlsx"
        
        return create_excel_response(result_df, file_name, "Component Comprehensive Report")
        
    except Exception as e:
        logger.error(f"Error in component comprehensive report: {str(e)}")
        return HttpResponse("Error generating component report", status=500)


def get_unique_cves_for_component_comprehensive(component):
    """
    Get unique CVEs for component with comprehensive data
    """
    try:
        releases = e_releases.objects.filter(sw_component=component)
        component_runs = runs.objects.filter(e_release_id__in=releases)
        
        cve_states = current_sw_state.objects.filter(
            last_modified_run_id__in=component_runs
        ).select_related('cve_id').prefetch_related('cpe_string')
        
        cve_data = {}
        for cve_state in cve_states:
            cve_id = cve_state.cve_id
            if cve_id not in cve_data:
                cpe_info = get_comprehensive_cpe_data(cve_state)
                attack_vector = get_attack_vector_for_cve(cve_id)
                
                cve_data[cve_id] = {
                    'cve_id': cve_id,
                    'descriptions': cve_state.descriptions or '',
                    'cvss_score': cve_state.cvss_score or '',
                    'CVSS_Priority': cve_state.CVSS_Priority or '',
                    'Analysis_Priority': cve_state.Analysis_Priority or '',
                    'attack_vector': attack_vector,
                    'cpe_string': cpe_info.get('cpe_string', ''),
                    'sw_name': cpe_info.get('sw_name', ''),
                    'sw_version': cpe_info.get('sw_version', ''),
                    'architecture': cpe_info.get('architecture', ''),
                }
        
        return cve_data
        
    except Exception as e:
        logger.error(f"Error getting component CVEs: {str(e)}")
        return {}


def build_component_comprehensive_matrix(releases, all_cves):
    """
    Build comprehensive component matrix with all releases
    """
    cve_list = []
    for cve_id, cve_data in all_cves.items():
        base_data = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'SW Version': cve_data['sw_version'],
            'Architecture': cve_data['architecture'],
            'CVSS Score': cve_data['cvss_score'],
            'CVSS Priority': cve_data['CVSS_Priority'],
            'Analysis Priority': cve_data['Analysis_Priority'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        # Add comprehensive columns for each release
        for release in releases:
            details = get_comprehensive_release_details(cve_id, release)
            col_prefix = release.e_release_version
            
            base_data.update({
                f"{col_prefix}_Status": details['status'],
                f"{col_prefix}_Comments": details['comments'],
                f"{col_prefix}_Closed_At": details['closed_at'],
                f"{col_prefix}_JIRA_Ticket": details['jira_ticket'],
                f"{col_prefix}_JIRA_Status": details['jira_status'],
                f"{col_prefix}_STARC_Ticket": details['starc_ticket'],
                f"{col_prefix}_STARC_Status": details['starc_status'],
                f"{col_prefix}_True_Positive": details['true_positive_reason'],
                f"{col_prefix}_False_Positive": details['false_positive_reason'],
                f"{col_prefix}_KB_Modified": details['kb_modified'],
                f"{col_prefix}_CAVD_No": details['cavd_no'],
            })
        
        cve_list.append(base_data)
    
    return pd.DataFrame(cve_list)


# ALTERNATIVE MULTI-SHEET APPROACH

def generate_project_alternative_report(request, r_id):
    """
    Generate clean multi-sheet project report (Alternative Approach)
    """
    try:
        runs_instance = runs.objects.select_related('sw_branch_id__project_id').get(id=r_id)
        project = runs_instance.sw_branch_id.project_id
        
        logger.info(f"Generating alternative project report for: {project.project_name}")
        
        # Get data
        branches_data = get_project_structure_comprehensive(project)
        all_cves = get_unique_cves_for_project_comprehensive(project)
        
        # Create multiple sheets
        sheets_data = create_alternative_project_sheets(branches_data, all_cves)
        
        file_name = f"{project.project_name}_alternative_report.xlsx"
        return create_multi_sheet_excel_response(sheets_data, file_name)
        
    except Exception as e:
        logger.error(f"Error in alternative project report: {str(e)}")
        return HttpResponse("Error generating alternative project report", status=500)


def create_alternative_project_sheets(branches_data, all_cves):
    """
    Create multiple sheets for alternative format
    """
    sheets = {}
    
    # Sheet 1: Summary Matrix (CVE + Simple Status)
    summary_data = []
    for cve_id, cve_data in all_cves.items():
        row = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'CVSS Score': cve_data['cvss_score'],
            'CVSS Priority': cve_data['CVSS_Priority'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        # Simple status for each branch/component
        for branch_name, branch_info in branches_data.items():
            if branch_info['type'] == 'branch_with_components':
                for comp_name, release in branch_info['components'].items():
                    col_name = f"{branch_name}_{comp_name}_Status"
                    details = get_comprehensive_release_details(cve_id, release)
                    row[col_name] = details['status']
            else:
                details = get_comprehensive_release_details(cve_id, branch_info['release'])
                row[f"{branch_name}_Status"] = details['status']
        
        summary_data.append(row)
    
    sheets['Summary'] = pd.DataFrame(summary_data)
    
    # Sheet 2: Detailed View (Vertical Format)
    detailed_data = []
    for cve_id, cve_data in all_cves.items():
        for branch_name, branch_info in branches_data.items():
            if branch_info['type'] == 'branch_with_components':
                for comp_name, release in branch_info['components'].items():
                    details = get_comprehensive_release_details(cve_id, release)
                    detailed_data.append({
                        'CVE ID': cve_id,
                        'Branch': branch_name,
                        'Component': comp_name,
                        'Release': release.e_release_version if release else '',
                        'Status': details['status'],
                        'CVSS Score': cve_data['cvss_score'],
                        'Priority': cve_data['CVSS_Priority'],
                        'Comments': details['comments'],
                        'JIRA Ticket': details['jira_ticket'],
                        'STARC Ticket': details['starc_ticket'],
                        'Closed At': details['closed_at'],
                        'True Positive': details['true_positive_reason'],
                        'False Positive': details['false_positive_reason'],
                        'KB Modified': details['kb_modified'],
                        'CAVD No': details['cavd_no'],
                    })
            else:
                details = get_comprehensive_release_details(cve_id, branch_info['release'])
                detailed_data.append({
                    'CVE ID': cve_id,
                    'Branch': branch_name,
                    'Component': '',
                    'Release': branch_info['release'].e_release_version if branch_info['release'] else '',
                    'Status': details['status'],
                    'CVSS Score': cve_data['cvss_score'],
                    'Priority': cve_data['CVSS_Priority'],
                    'Comments': details['comments'],
                    'JIRA Ticket': details['jira_ticket'],
                    'STARC Ticket': details['starc_ticket'],
                    'Closed At': details['closed_at'],
                    'True Positive': details['true_positive_reason'],
                    'False Positive': details['false_positive_reason'],
                    'KB Modified': details['kb_modified'],
                    'CAVD No': details['cavd_no'],
                })
    
    sheets['Details'] = pd.DataFrame(detailed_data)
    
    # Sheet 3+: Per-Branch Analysis
    for branch_name, branch_info in branches_data.items():
        branch_data = []
        for cve_id, cve_data in all_cves.items():
            if branch_info['type'] == 'branch_with_components':
                for comp_name, release in branch_info['components'].items():
                    details = get_comprehensive_release_details(cve_id, release)
                    if details['status'] not in ['N/A', 'Not Found']:
                        branch_data.append({
                            'CVE ID': cve_id,
                            'Component': comp_name,
                            'Description': cve_data['descriptions'],
                            'Status': details['status'],
                            'CVSS Score': cve_data['cvss_score'],
                            'Comments': details['comments'],
                            'JIRA Ticket': details['jira_ticket'],
                            'Closed At': details['closed_at'],
                        })
            else:
                details = get_comprehensive_release_details(cve_id, branch_info['release'])
                if details['status'] not in ['N/A', 'Not Found']:
                    branch_data.append({
                        'CVE ID': cve_id,
                        'Component': 'Direct Release',
                        'Description': cve_data['descriptions'],
                        'Status': details['status'],
                        'CVSS Score': cve_data['cvss_score'],
                        'Comments': details['comments'],
                        'JIRA Ticket': details['jira_ticket'],
                        'Closed At': details['closed_at'],
                    })
        
        if branch_data:
            sheets[f'Branch_{branch_name}'] = pd.DataFrame(branch_data)
    
    return sheets


def generate_branch_alternative_report(request, r_id):
    """
    Generate alternative branch-level report
    """
    try:
        runs_instance = runs.objects.select_related('sw_branch_id').get(id=r_id)
        branch = runs_instance.sw_branch_id
        
        branch_data = get_branch_structure_comprehensive(branch)
        all_cves = get_unique_cves_for_branch_comprehensive(branch)
        
        sheets_data = create_alternative_branch_sheets(branch_data, all_cves, branch.name)
        
        file_name = f"{branch.project_id.project_name}_{branch.name}_alternative.xlsx"
        return create_multi_sheet_excel_response(sheets_data, file_name)
        
    except Exception as e:
        logger.error(f"Error in alternative branch report: {str(e)}")
        return HttpResponse("Error generating alternative branch report", status=500)


def create_alternative_branch_sheets(branch_data, all_cves, branch_name):
    """
    Create alternative branch sheets
    """
    sheets = {}
    
    # Summary sheet
    summary_data = []
    for cve_id, cve_data in all_cves.items():
        row = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'CVSS Score': cve_data['cvss_score'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        for name, release in branch_data['data'].items():
            details = get_comprehensive_release_details(cve_id, release)
            row[f"{name}_Status"] = details['status']
        
        summary_data.append(row)
    
    sheets['Summary'] = pd.DataFrame(summary_data)
    
    # Detailed sheet
    detailed_data = []
    for cve_id, cve_data in all_cves.items():
        for name, release in branch_data['data'].items():
            details = get_comprehensive_release_details(cve_id, release)
            detailed_data.append({
                'CVE ID': cve_id,
                'Component/Release': name,
                'Status': details['status'],
                'Description': cve_data['descriptions'],
                'CVSS Score': cve_data['cvss_score'],
                'Comments': details['comments'],
                'JIRA Ticket': details['jira_ticket'],
                'STARC Ticket': details['starc_ticket'],
                'Closed At': details['closed_at'],
                'KB Modified': details['kb_modified'],
                'CAVD No': details['cavd_no'],
            })
    
    sheets['Details'] = pd.DataFrame(detailed_data)
    
    return sheets


def generate_component_alternative_report(request, r_id):
    """
    Generate alternative component-level report
    """
    try:
        component_id = request.GET.get("component_id", r_id)
        component = sw_components.objects.select_related('sw_branch__project_id').get(id=component_id)
        
        releases = e_releases.objects.filter(sw_component=component).order_by('-creation_date')
        all_cves = get_unique_cves_for_component_comprehensive(component)
        
        sheets_data = create_alternative_component_sheets(releases, all_cves, component.component_name)
        
        project_name = component.sw_branch.project_id.project_name
        branch_name = component.sw_branch.name
        file_name = f"{project_name}_{branch_name}_{component.component_name}_alternative.xlsx"
        
        return create_multi_sheet_excel_response(sheets_data, file_name)
        
    except Exception as e:
        logger.error(f"Error in alternative component report: {str(e)}")
        return HttpResponse("Error generating alternative component report", status=500)


def create_alternative_component_sheets(releases, all_cves, component_name):
    """
    Create alternative component sheets
    """
    sheets = {}
    
    # Summary sheet
    summary_data = []
    for cve_id, cve_data in all_cves.items():
        row = {
            'CVE ID': cve_id,
            'Description': cve_data['descriptions'],
            'CPE String': cve_data['cpe_string'],
            'SW Name': cve_data['sw_name'],
            'CVSS Score': cve_data['cvss_score'],
            'Attack Vector': cve_data['attack_vector'],
        }
        
        for release in releases:
            details = get_comprehensive_release_details(cve_id, release)
            row[f"{release.e_release_version}_Status"] = details['status']
        
        summary_data.append(row)
    
    sheets['Summary'] = pd.DataFrame(summary_data)
    
    # Detailed sheet
    detailed_data = []
    for cve_id, cve_data in all_cves.items():
        for release in releases:
            details = get_comprehensive_release_details(cve_id, release)
            detailed_data.append({
                'CVE ID': cve_id,
                'Release': release.e_release_version,
                'Status': details['status'],
                'Description': cve_data['descriptions'],
                'CVSS Score': cve_data['cvss_score'],
                'Comments': details['comments'],
                'JIRA Ticket': details['jira_ticket'],
                'STARC Ticket': details['starc_ticket'],
                'Closed At': details['closed_at'],
                'True Positive': details['true_positive_reason'],
                'False Positive': details['false_positive_reason'],
                'KB Modified': details['kb_modified'],
                'CAVD No': details['cavd_no'],
            })
    
    sheets['Details'] = pd.DataFrame(detailed_data)
    
    return sheets


# RELEASE LEVEL REPORT

def generate_release_level_report(request, r_id):
    """
    Generate enhanced release-level report with all fields
    """
    try:
        e_release_instance = e_releases.objects.get(id=r_id)
        filter_method = request.GET.get("filter_method")
        filter_dict = None
        
        if filter_method:
            filter_dict = request.GET.dict()
        
        result_df, file_name = enhanced_release_report_generate(e_release_instance, filter_dict)
        return create_excel_response(result_df, file_name, "Enhanced Release Report")
        
    except Exception as e:
        logger.error(f"Error in release report: {str(e)}")
        return HttpResponse("Error generating release report", status=500)


def enhanced_release_report_generate(e_release_id, filter_dict=None):
    """
    Enhanced release report generation with all requested fields
    """
    try:
        run_id = runs.objects.filter(e_release_id=e_release_id).order_by('-id').first()
        if not run_id:
            return pd.DataFrame(), "no_data.xlsx"
        
        # Get queryset with all related data
        queryset = current_sw_state.objects.filter(
            last_modified_run_id=run_id
        ).select_related('cve_id').prefetch_related('cpe_string')
        
        # Apply filters if provided
        if filter_dict:
            queryset = enhanced_report_filter(filter_dict, queryset)
        
        if not queryset.exists():
            return pd.DataFrame(), "no_data.xlsx"
        
        # Process data with all required fields
        cve_data = []
        for cve_state in queryset:
            data_row = process_enhanced_cve_data(cve_state)
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
        file_name = f"{project_name}_{sw_name}_{e_release_version}_enhanced.xlsx"
        
        return df, file_name
        
    except Exception as e:
        logger.error(f"Error in enhanced release report: {str(e)}")
        return pd.DataFrame(), "error.xlsx"


def process_enhanced_cve_data(cve_state):
    """
    Process individual CVE data with all requested fields
    """
    try:
        # Get comprehensive CPE data
        cpe_data = get_comprehensive_cpe_data(cve_state)
        
        # Get attack vector
        attack_vector = get_attack_vector_for_cve(cve_state.cve_id)
        
        # Get comments
        comments = current_sw_state_comments.objects.filter(
            cve_id=cve_state
        ).values_list('comment', flat=True)
        comment_str = ' | '.join([c for c in comments if c])
        
        # Get JIRA details
        jira_detail = jira_details.objects.filter(cve_id=cve_state).first()
        jira_status = jira_detail.jira_status if jira_detail else ''
        
        # Format KB modification
        kb_modified = ""
        if cve_state.last_modified_by_knowledgebase == 1:
            kb_modified = "KB Modified"
        elif cve_state.last_modified_by_knowledgebase == 2:
            kb_modified = "System Modified"
        
        # Get CVSS data for all versions
        cvss_versions = get_all_cvss_versions(cve_state.cve_id)
        
        # Build comprehensive data dictionary
        data_dict = {
            "CVE ID": cve_state.cve_id,
            "Description": cve_state.descriptions or '',
            "CPE String": cpe_data['cpe_string'],
            "SW Name": cpe_data['sw_name'],
            "SW Version": cpe_data['sw_version'],
            "Architecture": cpe_data['architecture'],
            "Tool State": get_tool_state_name(cve_state.tool_state),
            "Analysis Priority": cve_state.Analysis_Priority or '',
            "CVSS Score": cve_state.cvss_score or '',
            "CVSS Priority": cve_state.CVSS_Priority or '',
            "Attack Vector": attack_vector,
            "Comments": comment_str,
            "Closed At": cve_state.closed or '',
            "JIRA Ticket": cve_state.jira_ticket or '',
            "JIRA Status": jira_status,
            "STARC Ticket": cve_state.starc_ticket or '',
            "STARC Status": cve_state.starc_status or '',
            "KB Modified": kb_modified,
            "CAVD No": cve_state.cavd_no or '',
        }
        
        # Add CVSS data for all versions
        for version in ['2.0', '3.0', '3.1', '4.0']:
            version_data = cvss_versions.get(version, {})
            data_dict.update({
                f"CVSS {version} Score": version_data.get('score', ''),
                f"CVSS {version} Severity": version_data.get('severity', ''),
                f"CVSS {version} Vector": version_data.get('vector', ''),
                f"CVSS {version} Attack Vector": version_data.get('attack_vector', ''),
            })
        
        # Add reason fields
        if cve_state.true_positive_reason:
            data_dict["True Positive Reason"] = format_reason(cve_state.true_positive_reason)
        
        if cve_state.false_positive_reason:
            data_dict["False Positive Reason"] = format_reason(cve_state.false_positive_reason)
        
        return data_dict
        
    except Exception as e:
        logger.error(f"Error processing enhanced CVE {cve_state.cve_id}: {str(e)}")
        return None


# UTILITY FUNCTIONS

def format_reason(reason):
    """
    Format true/false positive reasons
    """
    if not reason:
        return ""
    
    try:
        parts = reason.split(" ")
        if len(parts) >= 2:
            config_status = "set" if "true" in reason.lower() else "not set"
            return f"This CVE is about {parts[0]} and its related Config Name is {parts[1]} which is {config_status} according to config file"
        else:
            presence = "present" if "true" in reason.lower() else "not present"
            return f"This CVE is about {parts[0]} {presence} in the compile log"
    except Exception:
        return reason


def get_all_cvss_versions(cve_id):
    """
    Get CVSS data for all versions efficiently
    """
    cvss_data = {}
    try:
        cve_obj = CVE.objects.get(id=cve_id)
        cvss_objects = CVSSData.objects.filter(cve=cve_obj).order_by('-id')
        
        for cvss in cvss_objects:
            version = cvss.version
            if version not in cvss_data:
                cvss_data[version] = {
                    'score': cvss.base_score,
                    'severity': cvss.base_severity,
                    'vector': cvss.vector_string,
                    'attack_vector': cvss.attack_vector,
                }
    except Exception as e:
        logger.error(f"Error getting CVSS versions: {str(e)}")
    
    return cvss_data


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


# ENHANCED FILTERING

def enhanced_report_filter(cve_dict, current_sw_state_instance):
    """
    Enhanced filtering function with comprehensive error handling
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
        
        # Apply filters
        if cve_search:
            current_sw_state_instance = apply_enhanced_cve_filter(current_sw_state_instance, cve_search)
        
        if severity_search:
            current_sw_state_instance = apply_enhanced_severity_filter(current_sw_state_instance, severity_search)
        
        if tool_status_search:
            tool_status_list = [int(x.strip()) for x in tool_status_search.split(",") if x.strip().isdigit()]
            if tool_status_list:
                current_sw_state_instance = current_sw_state_instance.filter(tool_state__in=tool_status_list)
        
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
                logger.warning(f"Invalid date format: {created_date}")
        
        if checked_cves:
            cve_list = [x.strip() for x in checked_cves.split(",") if x.strip()]
            if cve_list:
                current_sw_state_instance = current_sw_state_instance.filter(cve_id__in=cve_list)
        
        return current_sw_state_instance
        
    except Exception as e:
        logger.error(f"Error in enhanced report filter: {str(e)}")
        return current_sw_state_instance


def apply_enhanced_cve_filter(queryset, cve_search):
    """
    Apply enhanced CVE-specific filters
    """
    try:
        if ":" in cve_search:
            parts = cve_search.split(":", 1)
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
        logger.error(f"Error in enhanced CVE filter: {str(e)}")
        return queryset


def apply_enhanced_severity_filter(queryset, severity_search):
    """
    Apply enhanced severity filters
    """
    try:
        severity_parts = [x.strip() for x in severity_search.split(",")]
        severity_list = [x for x in severity_parts if not x.replace(".", "").isdigit() and x != "none"]
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
        logger.error(f"Error in enhanced severity filter: {str(e)}")
        return queryset


# EXCEL CREATION FUNCTIONS

def create_excel_response(df, file_name, sheet_name="Report"):
    """
    Create optimized Excel response with enhanced formatting
    """
    try:
        if df.empty:
            df = pd.DataFrame({"Message": ["No data available"]})
        
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)
            
            # Enhanced formatting
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
                adjusted_width = min(max_length + 2, 80)
                worksheet.column_dimensions[column_letter].width = adjusted_width
            
            # Freeze header row
            worksheet.freeze_panes = 'A2'
            
            # Add filters
            if df.shape[0] > 0:
                worksheet.auto_filter.ref = f"A1:{chr(64 + df.shape[1])}{df.shape[0] + 1}"
        
        output.seek(0)
        
        response = HttpResponse(
            output.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        
        logger.info(f"Excel report generated: {file_name}, Shape: {df.shape}")
        return response
        
    except Exception as e:
        logger.error(f"Error creating Excel response: {str(e)}")
        return HttpResponse("Error creating Excel file", status=500)


def create_multi_sheet_excel_response(sheets_data, file_name):
    """
    Create multi-sheet Excel response
    """
    try:
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            for sheet_name, df in sheets_data.items():
                # Clean sheet name for Excel compatibility
                clean_name = sheet_name.replace('/', '_').replace('\\', '_')[:31]
                df.to_excel(writer, sheet_name=clean_name, index=False)
                
                # Format the sheet
                workbook = writer.book
                worksheet = writer.sheets[clean_name]
                
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
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
                
                # Freeze header and add filters
                worksheet.freeze_panes = 'A2'
                if df.shape[0] > 0:
                    worksheet.auto_filter.ref = f"A1:{chr(64 + df.shape[1])}{df.shape[0] + 1}"
        
        output.seek(0)
        
        response = HttpResponse(
            output.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        
        logger.info(f"Multi-sheet report generated: {file_name}")
        return response
        
    except Exception as e:
        logger.error(f"Error creating multi-sheet Excel: {str(e)}")
        return HttpResponse("Error creating Excel file", status=500)
