#ifndef BB_XML_H
#define BB_XML_H

#include <stdint.h>

#include <bb_errors.h>

/* A wrapper around mxmlLoadString()  
 */ 
void *init_xml(char *buf, ssize_t len);

/* A wrapper around mxmlDelete() 
 */
void free_xml(void *object);

/* Sets the element to value in the xml doc held by object.
 */
bb_ret set_node_value(void *object, char *element, char *value);

/* Returns the value of element in the xml doc held by object.
 */
char *get_node_value(void *object, char *element);

/* Returns a string representation of the xml doc
 */
bb_ret xml_to_str(void *object, char *buf, size_t len);

#endif
