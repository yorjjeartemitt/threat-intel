#include <gtk/gtk.h>
#include "api.h"
#include "db.h"
typedef struct {
	GtkWidget *entry;
	GtkWidget *label;
} AppWidgets;
static GtkWidget* make_menu_item(const char *label,GCallback callback,gpointer data) {
	GtkWidget *item=gtk_menu_item_new_with_label(label);
	if (callback)
		g_signal_connect(item,"activate",callback,data);
	return item;
}
static void menu_bar(GtkWidget *box){
	GtkWidget *menubar=gtk_menu_bar_new();

	GtkWidget *file_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("Quit",G_CALLBACK(gtk_main_quit),NULL));
	GtkWidget *file_item=gtk_menu_item_new_with_label("File");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item),file_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),file_item);

	GtkWidget *tools_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(tools_menu),make_menu_item("IP checker",NULL,NULL));
	gtk_menu_shell_append(GTK_MENU_SHELL(tools_menu),make_menu_item("Encode/Decode",NULL,NULL));

	GtkWidget *tools_item=gtk_menu_item_new_with_label("Tools");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(tools_item),tools_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),tools_item);
	gtk_box_pack_start(GTK_BOX(box),menubar,FALSE,FALSE,0);	
}

static void check_clicked(GtkButton *btn,gpointer data){
	AppWidgets *app_w=(AppWidgets *)data;
	const char *text=gtk_entry_get_text(GTK_ENTRY(app_w->entry));
	char *result=check_ip(text);
	if (result==NULL){
		gtk_label_set_text(GTK_LABEL(app_w->label),"error");
		return;
	}
	gtk_label_set_text(GTK_LABEL(app_w->label),result);
	free(result);
}
static void activate(GtkApplication *app,gpointer data){
	AppWidgets *w=(AppWidgets *)data;
	GtkWidget *window=gtk_application_window_new(app);
	GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,10);
	GtkWidget *button=gtk_button_new_with_label("check");
	menu_bar(box);

	gtk_window_set_title(GTK_WINDOW(window),"threat intel");
	gtk_window_set_default_size(GTK_WINDOW(window),400,300);
	
	w->entry=gtk_entry_new();
	w->label=gtk_label_new("");
	
	g_signal_connect(button,"clicked",G_CALLBACK(check_clicked),w);
	gtk_box_pack_start(GTK_BOX(box),w->entry,FALSE,FALSE,5);
	gtk_box_pack_start(GTK_BOX(box),button,FALSE,FALSE,5);
	gtk_box_pack_start(GTK_BOX(box),w->label,FALSE,FALSE,5);
	gtk_container_add(GTK_CONTAINER(window),box);
	gtk_widget_show_all(window);
}
int main(int argc,char **argv){
	db_init();
	AppWidgets widgets={0};
	
	GtkApplication *app=gtk_application_new("com.threatintel",0);
	g_signal_connect(app,"activate",G_CALLBACK(activate),&widgets);
	int status=g_application_run(G_APPLICATION(app),argc,argv);
	g_object_unref(app);
	return status;
}
