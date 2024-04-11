import frappe

def hide_share_button_on_employee_advance(doc, method):
    # Check if the document is of the 'Employee Advance' doctype and the workflow state is 'Approved'
    if doc.doctype == 'Employee Advance' and doc.workflow_state != 'Approved':
        frappe.web_form.set_df_property('share', 'hidden', 1)