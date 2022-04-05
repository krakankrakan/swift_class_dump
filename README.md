# swift_class_dump
Dumps Classes from Swift binaries. This might be useful for reverse-engineering Swift applications. Note that this is still a work-in-progress, so not all things might work as intended.

## Building
Build via `build.sh`.

## Example
An example output of `swift_class_dump`:
```
Class
	Name: ViewController
	FieldDescriptor:   0x29bc
	Fields:
		FieldName: 		webView
		MangledTypeName: 	So9WKWebViewCSgXw

		FieldName: 		progressBar
		MangledTypeName: 	So14UIProgressViewCSgXw

		FieldName: 		barView
		MangledTypeName: 	So6UIViewCSgXw

		FieldName: 		urlField
		MangledTypeName: 	So11UITextFieldCSgXw

		FieldName: 		backButton
		MangledTypeName: 	So15UIBarButtonItemCSgXw

		FieldName: 		forwardButton
		MangledTypeName: 	So15UIBarButtonItemCSgXw

		FieldName: 		reloadButton
		MangledTypeName: 	So15UIBarButtonItemCSgXw

		FieldName: 		urlStr
		MangledTypeName: 	SS

	Methods:
    ...
```