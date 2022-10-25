package com.epmedu.animeal.tabs

import androidx.annotation.StringRes
import com.epmedu.animeal.common.route.TabsRoute
import com.epmedu.animeal.resources.R

sealed class NavigationTab(val route: TabsRoute, val icon: Int, @StringRes val contentDescription: Int) {
    object Search : NavigationTab(
        route = TabsRoute.Search,
        icon = R.drawable.ic_search,
        contentDescription = R.string.tab_search
    )
    object Favorites : NavigationTab(
        route = TabsRoute.Favourites,
        icon = R.drawable.ic_favorites,
        contentDescription = R.string.tab_favourites
    )
    object Home : NavigationTab(
        route = TabsRoute.Home,
        icon = R.drawable.ic_home,
        contentDescription = R.string.tab_home
    )
    object Analytics : NavigationTab(
        route = TabsRoute.Analytics,
        icon = R.drawable.ic_analytics,
        contentDescription = R.string.tab_analytics
    )
    object More : NavigationTab(
        route = TabsRoute.More,
        icon = R.drawable.ic_more,
        contentDescription = R.string.tab_more
    )
}
