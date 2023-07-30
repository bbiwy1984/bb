#include <mxml.h>

#include <bb_xml.h>

void *init_xml(char *buf, ssize_t len)
{

    return (void*)mxmlLoadString(NULL, buf, MXML_NO_CALLBACK);
}

void free_xml(void *object)
{
    mxml_node_t *tree;

    tree = (mxml_node_t*)object;

    mxmlDelete(tree);
}

char *get_node_value(void *object, char *element)
{
    int ws;
    mxml_node_t *node;
    mxml_node_t *tree;

    tree = (mxml_node_t*)object;

    ws = 0;
    node = mxmlFindElement(tree, tree, element, NULL, NULL, MXML_DESCEND);
    
    if (node == NULL)
        return NULL;
    
    return (char*)mxmlGetText(node, &ws);
}

bb_ret set_node_value(void *object, char *element, char *value)
{
    int ws;
    mxml_node_t *tree;
    mxml_node_t *node;

    tree = (mxml_node_t*)object;

    ws = 0;
    node = mxmlFindElement(tree, tree, element, NULL, NULL, MXML_DESCEND);
    
    if (node == NULL)
        return XML_CANT_FIND_ELEMENT;
    if (mxmlSetText(node, ws, value) == -1)
        return XML_CANT_SET_TEXT;

    return ALL_GOOD;
}

bb_ret xml_to_str(void *object, char *buf, size_t len)
{
    mxml_node_t *tree;

    tree = (mxml_node_t*)object;

    mxmlSaveString(tree, buf, len, MXML_NO_CALLBACK);
    
    return ALL_GOOD;
}
