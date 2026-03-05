from django import forms


class ScanForm(forms.Form):
    indicator = forms.CharField(
        max_length=512,
        widget=forms.TextInput(attrs={
            "placeholder": "IP, domain, URL, file hash, or CVE ID",
            "autofocus": True,
            "autocomplete": "off",
        }),
    )
